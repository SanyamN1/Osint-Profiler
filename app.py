"""People OSINT Profiler — username, phone, email breach, name search."""
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import os
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
CORS(app)

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")          # HaveIBeenPwned
NUMVERIFY_KEY = os.getenv("NUMVERIFY_API_KEY", "")     # Phone lookup

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


# ─── Phone Lookup ────────────────────────────────────────────────────────────

def lookup_phone(number: str) -> dict:
    # Strip spaces/dashes for cleaner input
    number = number.strip().replace(" ", "").replace("-", "")
    if not NUMVERIFY_KEY:
        # Fallback: basic format info without API
        return {
            "status": "success",
            "number": number,
            "note": "Set NUMVERIFY_API_KEY for full carrier/line-type data",
            "country_code": number[:3] if number.startswith("+") else None,
        }
    try:
        r = requests.get(
            "http://apilayer.net/api/validate",
            params={"access_key": NUMVERIFY_KEY, "number": number, "format": 1},
            timeout=8,
        )
        d = r.json()
        if not d.get("valid"):
            return {"status": "error", "message": "Invalid or unrecognised number"}
        return {
            "status": "success",
            "number": d.get("international_format"),
            "local_format": d.get("local_format"),
            "valid": d.get("valid"),
            "country": d.get("country_name"),
            "country_code": d.get("country_code"),
            "location": d.get("location"),
            "carrier": d.get("carrier"),
            "line_type": d.get("line_type"),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── Email Breach Check ──────────────────────────────────────────────────────

def check_email_breach(email: str) -> dict:
    email = email.strip().lower()
    results = {"status": "success", "email": email, "breaches": [], "pastes": []}

    if not HIBP_API_KEY:
        results["note"] = "Set HIBP_API_KEY for breach data (haveibeenpwned.com)"
        return results

    headers = {"hibp-api-key": HIBP_API_KEY, "User-Agent": "OSINT-Profiler"}

    # Breaches
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers, params={"truncateResponse": "false"}, timeout=10
        )
        if r.status_code == 200:
            for b in r.json():
                results["breaches"].append({
                    "name": b.get("Name"),
                    "domain": b.get("Domain"),
                    "breach_date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", []),
                    "description": b.get("Description", "")[:200],
                })
        elif r.status_code == 404:
            pass  # no breaches — good
    except Exception as e:
        results["breach_error"] = str(e)

    # Pastes
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
            headers=headers, timeout=10
        )
        if r.status_code == 200:
            for p in r.json():
                results["pastes"].append({
                    "source": p.get("Source"),
                    "title": p.get("Title"),
                    "date": p.get("Date"),
                    "email_count": p.get("EmailCount"),
                })
    except Exception:
        pass

    results["breach_count"] = len(results["breaches"])
    results["paste_count"] = len(results["pastes"])
    return results


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

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "hibp_configured": bool(HIBP_API_KEY),
        "numverify_configured": bool(NUMVERIFY_KEY),
    })

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.getenv("PORT", 5001)))
