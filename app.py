"""People OSINT Profiler — username, phone, email breach, name search."""
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
CORS(app)

VERIPHONE_KEY = os.getenv("VERIPHONE_API_KEY", "")     # veriphone.io — free tier 1000/month

# ─── Username Checker ────────────────────────────────────────────────────────

PLATFORMS = {
    "GitHub":       "https://github.com/{}",
    "Twitter/X":    "https://twitter.com/{}",
    "Instagram":    "https://www.instagram.com/{}",
    "TikTok":       "https://www.tiktok.com/@{}",
    "Reddit":       "https://www.reddit.com/user/{}",
    "Pinterest":    "https://www.pinterest.com/{}",
    "Twitch":       "https://www.twitch.tv/{}",
    "YouTube":      "https://www.youtube.com/@{}",
    "LinkedIn":     "https://www.linkedin.com/in/{}",
    "Snapchat":     "https://www.snapchat.com/add/{}",
    "Telegram":     "https://t.me/{}",
    "Medium":       "https://medium.com/@{}",
    "Dev.to":       "https://dev.to/{}",
    "Keybase":      "https://keybase.io/{}",
    "Pastebin":     "https://pastebin.com/u/{}",
    "HackerNews":   "https://news.ycombinator.com/user?id={}",
    "ProductHunt":  "https://www.producthunt.com/@{}",
    "Replit":       "https://replit.com/@{}",
    "Gitlab":       "https://gitlab.com/{}",
    "Bitbucket":    "https://bitbucket.org/{}",
}

def check_username(username: str) -> dict:
    results = {"status": "success", "username": username, "found": [], "not_found": []}

    def probe(name, url_template):
        url = url_template.format(username)
        try:
            r = requests.get(url, timeout=6, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0"})
            # 200 = exists, 404 = not found; some sites redirect to login on 404
            taken = r.status_code == 200
            return name, url, taken
        except Exception:
            return name, url, None  # unknown

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(probe, n, u): n for n, u in PLATFORMS.items()}
        for f in as_completed(futures):
            name, url, taken = f.result()
            entry = {"platform": name, "url": url}
            if taken is True:
                results["found"].append(entry)
            elif taken is False:
                results["not_found"].append(entry)
            # None (error/unknown) silently dropped

    results["found"].sort(key=lambda x: x["platform"])
    results["not_found"].sort(key=lambda x: x["platform"])
    return results


# ─── Phone Lookup (veriphone.io) ─────────────────────────────────────────────

def lookup_phone(number: str) -> dict:
    number = number.strip().replace(" ", "").replace("-", "")
    if not VERIPHONE_KEY:
        return {"status": "error", "message": "Set VERIPHONE_API_KEY (free at veriphone.io — 1000 lookups/month)"}
    try:
        r = requests.get(
            "https://api.veriphone.io/v2/verify",
            params={"phone": number, "default_country": "IN"},
            headers={"Authorization": f"Bearer {VERIPHONE_KEY}"},
            timeout=8,
        )
        d = r.json()
        if not d.get("phone_valid"):
            return {"status": "error", "message": "Invalid or unrecognised number"}
        return {
            "status": "success",
            "number": d.get("international_number"),
            "local": d.get("local_number"),
            "e164": d.get("e164"),
            "type": d.get("phone_type"),
            "region": d.get("phone_region"),
            "country": d.get("country"),
            "carrier": d.get("carrier"),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── Email Breach Check (emailrep.io — free, no key) ─────────────────────────

def check_email_breach(email: str) -> dict:
    email = email.strip().lower()
    try:
        r = requests.get(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": "osint-profiler"},
            timeout=10,
        )
        if r.status_code != 200:
            return {"status": "error", "message": f"emailrep.io returned {r.status_code}"}
        d = r.json()
        rep = d.get("details", {})
        return {
            "status": "success",
            "email": email,
            "reputation": d.get("reputation"),          # none / low / medium / high
            "suspicious": d.get("suspicious", False),
            "breach_count": rep.get("breach_count", 0),
            "breached": rep.get("breached", False),
            "last_breached_at": rep.get("last_seen_breached"),
            "malicious_activity": rep.get("malicious_activity", False),
            "spam": rep.get("spam", False),
            "disposable": rep.get("disposable", False),
            "free_provider": rep.get("free_provider", False),
            "profiles": rep.get("profiles", []),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── Name Search ─────────────────────────────────────────────────────────────

NAME_SEARCH_TEMPLATES = [
    ("LinkedIn",   "https://www.linkedin.com/search/results/people/?keywords={}"),
    ("Facebook",   "https://www.facebook.com/search/people/?q={}"),
    ("Twitter/X",  "https://twitter.com/search?q={}&f=user"),
    ("Instagram",  "https://www.instagram.com/explore/search/keyword/?q={}"),
    ("Google",     "https://www.google.com/search?q=%22{}%22+site:linkedin.com+OR+site:twitter.com+OR+site:facebook.com"),
    ("TikTok",     "https://www.tiktok.com/search/user?q={}"),
    ("GitHub",     "https://github.com/search?q={}&type=users"),
    ("Reddit",     "https://www.reddit.com/search/?q={}&type=user"),
    ("Pipl",       "https://pipl.com/search/?q={}"),
    ("Spokeo",     "https://www.spokeo.com/search?q={}"),
    ("BeenVerified","https://www.beenverified.com/people/search/?firstName={first}&lastName={last}"),
]

def search_name(name: str) -> dict:
    name = name.strip()
    parts = name.split()
    first = parts[0] if parts else name
    last = parts[-1] if len(parts) > 1 else ""
    encoded = name.replace(" ", "+")

    links = []
    for platform, template in NAME_SEARCH_TEMPLATES:
        if "{first}" in template:
            url = template.replace("{first}", first).replace("{last}", last)
        else:
            url = template.format(encoded)
        links.append({"platform": platform, "url": url})

    return {
        "status": "success",
        "name": name,
        "search_links": links,
        "note": "These are direct search links — click to open each platform's people search for this name.",
    }


# ─── Vehicle Lookup (India) ───────────────────────────────────────────────────

# State codes from Indian number plates
STATE_CODES = {
    "AN":"Andaman & Nicobar","AP":"Andhra Pradesh","AR":"Arunachal Pradesh",
    "AS":"Assam","BR":"Bihar","CG":"Chhattisgarh","CH":"Chandigarh",
    "DD":"Daman & Diu","DL":"Delhi","DN":"Dadra & Nagar Haveli","GA":"Goa",
    "GJ":"Gujarat","HP":"Himachal Pradesh","HR":"Haryana","JH":"Jharkhand",
    "JK":"Jammu & Kashmir","KA":"Karnataka","KL":"Kerala","LA":"Ladakh",
    "LD":"Lakshadweep","MH":"Maharashtra","ML":"Meghalaya","MN":"Manipur",
    "MP":"Madhya Pradesh","MZ":"Mizoram","NL":"Nagaland","OD":"Odisha",
    "PB":"Punjab","PY":"Puducherry","RJ":"Rajasthan","SK":"Sikkim",
    "TN":"Tamil Nadu","TR":"Tripura","TS":"Telangana","UK":"Uttarakhand",
    "UP":"Uttar Pradesh","WB":"West Bengal",
}

def lookup_vehicle(plate: str) -> dict:
    plate = plate.strip().upper().replace(" ", "").replace("-", "")
    if len(plate) < 6:
        return {"status": "error", "message": "Enter a valid Indian registration number (e.g. DL01AB1234)"}

    state_code = plate[:2]
    state = STATE_CODES.get(state_code, "Unknown State")
    rto_code = plate[:4]  # e.g. DL01

    return {
        "status": "success",
        "plate": plate,
        "state_code": state_code,
        "state": state,
        "rto_code": rto_code,
        "links": [
            {"label": "RC Details — CarInfo", "url": f"https://www.carinfo.app/rc-search/{plate}"},
            {"label": "E-Challan Check — Parivahan", "url": f"https://echallan.parivahan.gov.in/index/accused-challan"},
            {"label": "RC Status — Vahan (Official)", "url": "https://vahan.parivahan.gov.in/vahanservice/vahan/ui/statevalidation/homepage.xhtml"},
            {"label": "mParivahan App Lookup", "url": "https://mparivahan.app.link/"},
        ],
        "note": "Click a link to check full RC details, owner info, and challans on the respective platform.",
    }


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/username", methods=["POST"])
def api_username():
    data = request.get_json()
    if not data or not data.get("username"):
        return jsonify({"error": "username required"}), 400
    return jsonify(check_username(data["username"].strip()))

@app.route("/api/phone", methods=["POST"])
def api_phone():
    data = request.get_json()
    if not data or not data.get("number"):
        return jsonify({"error": "number required"}), 400
    return jsonify(lookup_phone(data["number"]))

@app.route("/api/email", methods=["POST"])
def api_email():
    data = request.get_json()
    if not data or not data.get("email"):
        return jsonify({"error": "email required"}), 400
    return jsonify(check_email_breach(data["email"]))

@app.route("/api/name", methods=["POST"])
def api_name():
    data = request.get_json()
    if not data or not data.get("name"):
        return jsonify({"error": "name required"}), 400
    return jsonify(search_name(data["name"]))

@app.route("/api/vehicle", methods=["POST"])
def api_vehicle():
    data = request.get_json()
    if not data or not data.get("plate"):
        return jsonify({"error": "plate required"}), 400
    return jsonify(lookup_vehicle(data["plate"]))

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "veriphone_configured": bool(VERIPHONE_KEY),
    })

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.getenv("PORT", 5001)))
