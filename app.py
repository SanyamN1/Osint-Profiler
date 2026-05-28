"""
OSINT Investigation Framework
Automates information gathering: WHOIS, DNS, email metadata, social footprint.
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import socket
import json
import re
import time
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import whois
import dns.resolver
import dns.reversename

app = Flask(__name__)
CORS(app)

# ─── API Keys ────────────────────────────────────────────────────────────────
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")          # Email lookup
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")           # IP/host intel
IPINFO_TOKEN   = os.getenv("IPINFO_TOKEN", "")             # IP geolocation
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")       # Domain reputation


# ─── Module: WHOIS ────────────────────────────────────────────────────────────

def gather_whois(target: str) -> dict:
    """Extract WHOIS registration data for a domain."""
    try:
        domain = extract_domain(target)
        w = whois.whois(domain)

        def safe_str(val):
            if val is None: return None
            if isinstance(val, list): return val[0].strftime("%Y-%m-%d") if hasattr(val[0], 'strftime') else str(val[0])
            if hasattr(val, 'strftime'): return val.strftime("%Y-%m-%d")
            return str(val)

        return {
            "status": "success",
            "domain": domain,
            "registrar": safe_str(w.registrar),
            "created": safe_str(w.creation_date),
            "expires": safe_str(w.expiration_date),
            "updated": safe_str(w.updated_date),
            "name_servers": [ns.lower() for ns in (w.name_servers or [])][:6],
            "status_codes": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            "emails": list(set(w.emails)) if w.emails else [],
            "org": safe_str(w.org),
            "country": safe_str(w.country),
            "registrant_name": safe_str(getattr(w, 'name', None)),
            "dnssec": str(getattr(w, 'dnssec', 'Unknown')),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── Module: DNS ──────────────────────────────────────────────────────────────

def gather_dns(target: str) -> dict:
    """Enumerate DNS records for a domain."""
    domain = extract_domain(target)
    records = {}

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []

    # Reverse DNS for A records
    reverse_dns = {}
    for ip in records.get("A", [])[:3]:
        try:
            rev_name = dns.reversename.from_address(ip)
            ptr = str(dns.resolver.resolve(rev_name, "PTR", lifetime=3)[0])
            reverse_dns[ip] = ptr
        except Exception:
            reverse_dns[ip] = None

    # SPF/DMARC analysis
    spf_record = next((r for r in records.get("TXT", []) if "v=spf" in r.lower()), None)
    dmarc_records = []
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        dmarc_records = [str(r) for r in dmarc_answers]
    except Exception:
        pass

    # MX hosts extraction
    mx_hosts = []
    for mx in records.get("MX", []):
        parts = mx.split()
        if len(parts) >= 2:
            mx_hosts.append({"priority": parts[0], "host": parts[1].rstrip(".")})

    return {
        "status": "success",
        "domain": domain,
        "records": records,
        "reverse_dns": reverse_dns,
        "mx_hosts": mx_hosts,
        "spf_record": spf_record,
        "dmarc_records": dmarc_records,
        "email_security": {
            "spf": bool(spf_record),
            "dmarc": bool(dmarc_records),
            "dkim_indicator": any("dkim" in r.lower() for r in records.get("TXT", []))
        }
    }


# ─── Module: IP Intelligence ─────────────────────────────────────────────────

def gather_ip_intel(target: str) -> dict:
    """Resolve domain to IPs and gather geolocation + ASN data."""
    domain = extract_domain(target)
    results = {"status": "success", "domain": domain, "ips": []}

    try:
        ips = list(set(socket.gethostbyname_ex(domain)[2]))
    except Exception as e:
        return {"status": "error", "message": str(e)}

    for ip in ips[:4]:
        ip_data = {"ip": ip}

        # IPInfo lookup
        try:
            headers = {"Authorization": f"Bearer {IPINFO_TOKEN}"} if IPINFO_TOKEN else {}
            resp = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=6)
            if resp.status_code == 200:
                info = resp.json()
                ip_data.update({
                    "hostname": info.get("hostname"),
                    "city": info.get("city"),
                    "region": info.get("region"),
                    "country": info.get("country"),
                    "org": info.get("org"),
                    "asn": info.get("org", "").split()[0] if info.get("org") else None,
                    "timezone": info.get("timezone"),
                    "loc": info.get("loc"),
                    "postal": info.get("postal"),
                })
        except Exception:
            pass

        # Shodan lookup
        if SHODAN_API_KEY:
            try:
                shodan_resp = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}",
                    timeout=8
                )
                if shodan_resp.status_code == 200:
                    sd = shodan_resp.json()
                    ip_data["shodan"] = {
                        "open_ports": sd.get("ports", [])[:20],
                        "vulns": list(sd.get("vulns", {}).keys())[:10],
                        "hostnames": sd.get("hostnames", [])[:5],
                        "tags": sd.get("tags", []),
                        "last_update": sd.get("last_update"),
                        "os": sd.get("os"),
                        "isp": sd.get("isp"),
                    }
            except Exception:
                pass

        results["ips"].append(ip_data)

    return results


# ─── Module: Email Footprint ──────────────────────────────────────────────────

def gather_email_intel(target: str) -> dict:
    """Find email addresses associated with a domain."""
    domain = extract_domain(target)
    results = {"status": "success", "domain": domain, "emails": [], "patterns": []}

    if HUNTER_API_KEY:
        try:
            resp = requests.get(
                f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_API_KEY}&limit=20",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                results["emails"] = [
                    {
                        "value": e["value"],
                        "type": e.get("type"),
                        "confidence": e.get("confidence"),
                        "first_name": e.get("first_name"),
                        "last_name": e.get("last_name"),
                        "position": e.get("position"),
                        "sources": len(e.get("sources", []))
                    }
                    for e in data.get("emails", [])
                ]
                results["patterns"] = data.get("pattern", "Unknown")
                results["total_found"] = data.get("meta", {}).get("results", 0)
                results["organization"] = data.get("organization")
        except Exception as e:
            results["error"] = str(e)
    else:
        results["note"] = "Set HUNTER_API_KEY for email enumeration"

    return results


# ─── Module: Domain Reputation ───────────────────────────────────────────────

def gather_domain_reputation(target: str) -> dict:
    """Check domain reputation via VirusTotal."""
    domain = extract_domain(target)
    results = {"status": "success", "domain": domain}

    if not VIRUSTOTAL_KEY:
        results["note"] = "Set VIRUSTOTAL_API_KEY for reputation data"
        return results

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            results.update({
                "reputation": data.get("reputation", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "categories": data.get("categories", {}),
                "creation_date": data.get("creation_date"),
                "registrar": data.get("registrar"),
                "tld": data.get("tld"),
                "popularity_ranks": data.get("popularity_ranks", {}),
            })
    except Exception as e:
        results["error"] = str(e)

    return results


# ─── Module: Technology Detection ────────────────────────────────────────────

def gather_tech_fingerprint(target: str) -> dict:
    """Detect web technologies via HTTP headers and response analysis."""
    domain = extract_domain(target)
    url = f"https://{domain}"
    results = {"status": "success", "domain": domain, "technologies": [], "headers": {}}

    try:
        resp = requests.get(url, timeout=8, allow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (compatible; OSINT-Framework/1.0)"
        })

        # Interesting security & tech headers
        interesting_headers = [
            "server", "x-powered-by", "x-frame-options", "content-security-policy",
            "x-xss-protection", "strict-transport-security", "x-content-type-options",
            "via", "cf-ray", "x-vercel-id", "x-amz-cf-id", "x-cache",
            "set-cookie", "www-authenticate", "x-generator", "x-drupal-cache"
        ]
        for h in interesting_headers:
            val = resp.headers.get(h)
            if val:
                results["headers"][h] = val[:200]

        # Technology detection from headers
        server = resp.headers.get("server", "").lower()
        powered = resp.headers.get("x-powered-by", "").lower()
        body_snippet = resp.text[:5000].lower()

        techs = []
        tech_sigs = {
            "Nginx": "nginx" in server,
            "Apache": "apache" in server,
            "IIS": "iis" in server or "microsoft-iis" in server,
            "Cloudflare": "cloudflare" in server or "cf-ray" in resp.headers,
            "AWS CloudFront": "cloudfront" in resp.headers.get("via","").lower() or "x-amz-cf-id" in resp.headers,
            "Vercel": "x-vercel-id" in resp.headers,
            "PHP": "php" in powered,
            "WordPress": "wp-content" in body_snippet or "wordpress" in body_snippet,
            "React": "react" in body_snippet or "__react" in body_snippet,
            "Next.js": "__next" in body_snippet or "/_next/" in body_snippet,
            "Django": "csrftoken" in resp.headers.get("set-cookie","").lower(),
            "jQuery": "jquery" in body_snippet,
            "Bootstrap": "bootstrap" in body_snippet,
        }
        techs = [name for name, match in tech_sigs.items() if match]

        results["technologies"] = techs
        results["status_code"] = resp.status_code
        results["final_url"] = resp.url
        results["content_type"] = resp.headers.get("content-type", "")
        results["redirect_count"] = len(resp.history)

    except requests.exceptions.SSLError:
        results["ssl_error"] = True
        results["note"] = "SSL certificate error"
    except Exception as e:
        results["status"] = "error"
        results["message"] = str(e)

    return results


# ─── Helper ───────────────────────────────────────────────────────────────────

def extract_domain(target: str) -> str:
    """Extract base domain from URL, IP, or plain domain."""
    target = target.strip().lower()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    return parsed.netloc.split(":")[0]


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/investigate", methods=["POST"])
def investigate():
    data = request.get_json()
    if not data or "target" not in data:
        return jsonify({"error": "No target provided"}), 400

    target = data["target"].strip()
    modules = data.get("modules", ["whois", "dns", "ip", "email", "reputation", "tech"])

    results = {
        "target": target,
        "domain": extract_domain(target),
        "timestamp": int(time.time()),
        "modules": {}
    }

    module_map = {
        "whois": gather_whois,
        "dns": gather_dns,
        "ip": gather_ip_intel,
        "email": gather_email_intel,
        "reputation": gather_domain_reputation,
        "tech": gather_tech_fingerprint,
    }

    # Run modules in parallel
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(fn, target): key
            for key, fn in module_map.items()
            if key in modules
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results["modules"][key] = future.result()
            except Exception as e:
                results["modules"][key] = {"status": "error", "message": str(e)}

    return jsonify(results)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "hunter_configured": bool(HUNTER_API_KEY),
        "shodan_configured": bool(SHODAN_API_KEY),
        "ipinfo_configured": bool(IPINFO_TOKEN),
        "virustotal_configured": bool(VIRUSTOTAL_KEY),
    })


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.getenv("PORT", 5001)))
