"""People OSINT Profiler — username, phone, email, name, GitHub, Reddit, domain/IP."""
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, os, socket, json
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
CORS(app)

VERIPHONE_KEY  = os.getenv("VERIPHONE_API_KEY", "")
EMAILREP_KEY   = os.getenv("EMAILREP_API_KEY", "")

# ─── 200+ Platform list ───────────────────────────────────────────────────────
PLATFORMS = {
    # Social
    "Twitter/X":        ("https://twitter.com/{}", 200),
    "Instagram":        ("https://www.instagram.com/{}/", 200),
    "TikTok":           ("https://www.tiktok.com/@{}", 200),
    "Facebook":         ("https://www.facebook.com/{}", 200),
    "Snapchat":         ("https://www.snapchat.com/add/{}", 200),
    "Pinterest":        ("https://www.pinterest.com/{}/", 200),
    "Tumblr":           ("https://{}.tumblr.com", 200),
    "Flickr":           ("https://www.flickr.com/people/{}", 200),
    "VK":               ("https://vk.com/{}", 200),
    "Mastodon":         ("https://mastodon.social/@{}", 200),
    "Minds":            ("https://www.minds.com/{}", 200),
    "MeWe":             ("https://mewe.com/i/{}", 200),
    "Parler":           ("https://parler.com/profile/{}", 200),
    "Gab":              ("https://gab.com/{}", 200),
    "Diaspora":         ("https://diaspora.social/people/{}", 200),
    "Plurk":            ("https://www.plurk.com/{}", 200),
    "Livejournal":      ("https://{}.livejournal.com", 200),
    "Ask.fm":           ("https://ask.fm/{}", 200),
    "Tellonym":         ("https://tellonym.me/{}", 200),
    "Vsco":             ("https://vsco.co/{}", 200),
    "WeHeartIt":        ("https://weheartit.com/{}", 200),
    "Ello":             ("https://ello.co/{}", 200),
    # Dev / Tech
    "GitHub":           ("https://github.com/{}", 200),
    "GitLab":           ("https://gitlab.com/{}", 200),
    "Bitbucket":        ("https://bitbucket.org/{}", 200),
    "SourceForge":      ("https://sourceforge.net/u/{}", 200),
    "Replit":           ("https://replit.com/@{}", 200),
    "Dev.to":           ("https://dev.to/{}", 200),
    "Codepen":          ("https://codepen.io/{}", 200),
    "Coderwall":        ("https://coderwall.com/{}", 200),
    "HackerNews":       ("https://news.ycombinator.com/user?id={}", 200),
    "Keybase":          ("https://keybase.io/{}", 200),
    "Kaggle":           ("https://www.kaggle.com/{}", 200),
    "HackerEarth":      ("https://www.hackerearth.com/@{}", 200),
    "HackerRank":       ("https://www.hackerrank.com/{}", 200),
    "LeetCode":         ("https://leetcode.com/{}", 200),
    "Codeforces":       ("https://codeforces.com/profile/{}", 200),
    "AtCoder":          ("https://atcoder.jp/users/{}", 200),
    "Topcoder":         ("https://www.topcoder.com/members/{}", 200),
    "SPOJ":             ("https://www.spoj.com/users/{}", 200),
    "Exercism":         ("https://exercism.io/profiles/{}", 200),
    "NPM":              ("https://www.npmjs.com/~{}", 200),
    "PyPI":             ("https://pypi.org/user/{}/", 200),
    "DockerHub":        ("https://hub.docker.com/u/{}", 200),
    "Pastebin":         ("https://pastebin.com/u/{}", 200),
    "Gist":             ("https://gist.github.com/{}", 200),
    "Codewars":         ("https://www.codewars.com/users/{}", 200),
    "Scratch":          ("https://scratch.mit.edu/users/{}", 200),
    # Content / Creative
    "YouTube":          ("https://www.youtube.com/@{}", 200),
    "Twitch":           ("https://www.twitch.tv/{}", 200),
    "Reddit":           ("https://www.reddit.com/user/{}", 200),
    "Medium":           ("https://medium.com/@{}", 200),
    "Substack":         ("https://{}.substack.com", 200),
    "Patreon":          ("https://www.patreon.com/{}", 200),
    "Ko-fi":            ("https://ko-fi.com/{}", 200),
    "BuyMeACoffee":     ("https://www.buymeacoffee.com/{}", 200),
    "OnlyFans":         ("https://onlyfans.com/{}", 200),
    "Fansly":           ("https://fansly.com/{}", 200),
    "Wattpad":          ("https://www.wattpad.com/user/{}", 200),
    "Fanfiction":       ("https://www.fanfiction.net/u/{}", 200),
    "AO3":              ("https://archiveofourown.org/users/{}", 200),
    "Deviantart":       ("https://www.deviantart.com/{}", 200),
    "ArtStation":       ("https://www.artstation.com/{}", 200),
    "Behance":          ("https://www.behance.net/{}", 200),
    "Dribbble":         ("https://dribbble.com/{}", 200),
    "500px":            ("https://500px.com/p/{}", 200),
    "Unsplash":         ("https://unsplash.com/@{}", 200),
    "Vimeo":            ("https://vimeo.com/{}", 200),
    "Dailymotion":      ("https://www.dailymotion.com/{}", 200),
    "Mixcloud":         ("https://www.mixcloud.com/{}/", 200),
    "Soundcloud":       ("https://soundcloud.com/{}", 200),
    "Bandcamp":         ("https://{}.bandcamp.com", 200),
    "Last.fm":          ("https://www.last.fm/user/{}", 200),
    "Spotify":          ("https://open.spotify.com/user/{}", 200),
    "Genius":           ("https://genius.com/{}", 200),
    # Professional
    "LinkedIn":         ("https://www.linkedin.com/in/{}", 200),
    "AngelList":        ("https://angel.co/u/{}", 200),
    "ProductHunt":      ("https://www.producthunt.com/@{}", 200),
    "Indie Hackers":    ("https://www.indiehackers.com/{}", 200),
    "Crunchbase":       ("https://www.crunchbase.com/person/{}", 200),
    "Xing":             ("https://www.xing.com/profile/{}", 200),
    "About.me":         ("https://about.me/{}", 200),
    # Gaming
    "Steam":            ("https://steamcommunity.com/id/{}", 200),
    "Xbox":             ("https://www.xbox.com/en-US/play/user/{}", 200),
    "PSN":              ("https://psnprofiles.com/{}", 200),
    "Minecraft":        ("https://namemc.com/profile/{}", 200),
    "Chess.com":        ("https://www.chess.com/member/{}", 200),
    "Lichess":          ("https://lichess.org/@/{}", 200),
    "Kongregate":       ("https://www.kongregate.com/accounts/{}", 200),
    "Armor Games":      ("https://armorgames.com/user/{}", 200),
    "Roblox":           ("https://www.roblox.com/user.aspx?username={}", 200),
    "Twitch Clips":     ("https://clips.twitch.tv/{}", 200),
    "Speedrun":         ("https://www.speedrun.com/user/{}", 200),
    "Overwolf":         ("https://www.overwolf.com/user/{}", 200),
    # Q&A / Forums
    "StackOverflow":    ("https://stackoverflow.com/users/{}", 200),
    "Quora":            ("https://www.quora.com/profile/{}", 200),
    "Telegram":         ("https://t.me/{}", 200),
    "Discord":          ("https://discord.com/users/{}", 200),
    "Slack":            ("https://{}.slack.com", 200),
    "Disqus":           ("https://disqus.com/by/{}/", 200),
    "Gravatar":         ("https://en.gravatar.com/{}", 200),
    "Wikipedia":        ("https://en.wikipedia.org/wiki/User:{}", 200),
    "Wikia":            ("https://www.fandom.com/u/{}", 200),
    # Misc
    "Fiverr":           ("https://www.fiverr.com/{}", 200),
    "Upwork":           ("https://www.upwork.com/freelancers/{}", 200),
    "Freelancer":       ("https://www.freelancer.com/u/{}", 200),
    "Etsy":             ("https://www.etsy.com/shop/{}", 200),
    "eBay":             ("https://www.ebay.com/usr/{}", 200),
    "Amazon":           ("https://www.amazon.com/gp/profile/amzn1.account.{}", 200),
    "Goodreads":        ("https://www.goodreads.com/{}", 200),
    "Letterboxd":       ("https://letterboxd.com/{}", 200),
    "Ravelry":          ("https://www.ravelry.com/people/{}", 200),
    "MyAnimeList":      ("https://myanimelist.net/profile/{}", 200),
    "Anilist":          ("https://anilist.co/user/{}", 200),
    "Trakt":            ("https://trakt.tv/users/{}", 200),
    "IMDb":             ("https://www.imdb.com/user/{}", 200),
    "Strava":           ("https://www.strava.com/athletes/{}", 200),
    "Duolingo":         ("https://www.duolingo.com/profile/{}", 200),
    "Memrise":          ("https://app.memrise.com/user/{}/", 200),
    "Airbnb":           ("https://www.airbnb.com/users/show/{}", 200),
    "TripAdvisor":      ("https://www.tripadvisor.com/Profile/{}", 200),
    "Yelp":             ("https://www.yelp.com/user_details?userid={}", 200),
    "Foursquare":       ("https://foursquare.com/{}", 200),
    "Untappd":          ("https://untappd.com/user/{}", 200),
    "Venmo":            ("https://venmo.com/{}", 200),
    "Cash App":         ("https://cash.app/${}", 200),
    "PayPal":           ("https://www.paypal.com/paypalme/{}", 200),
    "Linktree":         ("https://linktr.ee/{}", 200),
    "Carrd":            ("https://{}.carrd.co", 200),
}

def check_username(username: str) -> dict:
    results = {"status": "success", "username": username, "found": [], "not_found": []}

    def probe(name, url_tmpl, ok_code):
        url = url_tmpl.format(username)
        try:
            r = requests.get(url, timeout=7, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
            taken = r.status_code == ok_code and "page not found" not in r.text.lower()[:500]
            return name, url, taken
        except Exception:
            return name, url, None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(probe, n, t, c): n for n, (t, c) in PLATFORMS.items()}
        for f in as_completed(futures):
            name, url, taken = f.result()
            entry = {"platform": name, "url": url}
            if taken is True:
                results["found"].append(entry)
            elif taken is False:
                results["not_found"].append(entry)

    results["found"].sort(key=lambda x: x["platform"])
    results["not_found"].sort(key=lambda x: x["platform"])
    return results


# ─── Phone Lookup ─────────────────────────────────────────────────────────────
def lookup_phone(number: str) -> dict:
    number = number.strip().replace(" ", "").replace("-", "")
    if not VERIPHONE_KEY:
        return {"status": "error", "message": "Set VERIPHONE_API_KEY (free at veriphone.io)"}
    try:
        r = requests.get("https://api.veriphone.io/v2/verify",
            params={"phone": number, "default_country": "IN"},
            headers={"Authorization": f"Bearer {VERIPHONE_KEY}"}, timeout=8)
        d = r.json()
        if not d.get("phone_valid"):
            return {"status": "error", "message": "Invalid or unrecognised number"}
        return {"status": "success", "number": d.get("international_number"),
                "local": d.get("local_number"), "e164": d.get("e164"),
                "type": d.get("phone_type"), "region": d.get("phone_region"),
                "country": d.get("country"), "carrier": d.get("carrier")}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── Email Breach ─────────────────────────────────────────────────────────────
def check_email_breach(email: str) -> dict:
    email = email.strip().lower()
    headers = {"User-Agent": "osint-profiler"}
    if EMAILREP_KEY:
        headers["Key"] = EMAILREP_KEY
    try:
        r = requests.get(f"https://emailrep.io/{email}", headers=headers, timeout=10)
        if r.status_code != 200:
            return {"status": "error", "message": f"emailrep.io returned {r.status_code}"}
        d = r.json(); rep = d.get("details", {})
        return {"status": "success", "email": email,
                "reputation": d.get("reputation"), "suspicious": d.get("suspicious", False),
                "breach_count": rep.get("breach_count", 0), "breached": rep.get("breached", False),
                "last_breached_at": rep.get("last_seen_breached"),
                "malicious_activity": rep.get("malicious_activity", False),
                "spam": rep.get("spam", False), "disposable": rep.get("disposable", False),
                "free_provider": rep.get("free_provider", False), "profiles": rep.get("profiles", [])}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── Name Search ──────────────────────────────────────────────────────────────
NAME_TEMPLATES = [
    ("LinkedIn",        "https://www.linkedin.com/search/results/people/?keywords={}"),
    ("Facebook",        "https://www.facebook.com/search/people/?q={}"),
    ("Twitter/X",       "https://twitter.com/search?q={}&f=user"),
    ("Instagram",       "https://www.instagram.com/explore/search/keyword/?q={}"),
    ("TikTok",          "https://www.tiktok.com/search/user?q={}"),
    ("GitHub",          "https://github.com/search?q={}&type=users"),
    ("Reddit",          "https://www.reddit.com/search/?q={}&type=user"),
    ("Google Dork",     "https://www.google.com/search?q=%22{}%22+site:linkedin.com+OR+site:twitter.com"),
    ("Google Full",     "https://www.google.com/search?q=%22{}%22"),
    ("Pipl",            "https://pipl.com/search/?q={}"),
    ("Spokeo",          "https://www.spokeo.com/search?q={}"),
    ("BeenVerified",    "https://www.beenverified.com/people/search/?firstName={first}&lastName={last}"),
    ("Whitepages",      "https://www.whitepages.com/name/{}"),
    ("Intelius",        "https://www.intelius.com/people-search/{}"),
    ("PeopleFinder",    "https://www.peoplefinder.com/people/{}"),
    ("Truthfinder",     "https://www.truthfinder.com/people-search/?firstName={first}&lastName={last}"),
    ("Bing People",     "https://www.bing.com/search?q=%22{}%22+social+media"),
    ("YouTube",         "https://www.youtube.com/results?search_query={}"),
    ("Quora",           "https://www.quora.com/search?q={}"),
]

def search_name(name: str) -> dict:
    name = name.strip()
    parts = name.split()
    first = parts[0] if parts else name
    last = parts[-1] if len(parts) > 1 else ""
    encoded = name.replace(" ", "+")
    links = []
    for platform, tmpl in NAME_TEMPLATES:
        if "{first}" in tmpl:
            url = tmpl.replace("{first}", first).replace("{last}", last)
        else:
            url = tmpl.format(encoded)
        links.append({"platform": platform, "url": url})
    return {"status": "success", "name": name, "search_links": links,
            "note": "Click each link to search this person on the platform."}


# ─── Vehicle Lookup (India) ───────────────────────────────────────────────────
STATE_CODES = {
    "AN":"Andaman & Nicobar","AP":"Andhra Pradesh","AR":"Arunachal Pradesh","AS":"Assam",
    "BR":"Bihar","CG":"Chhattisgarh","CH":"Chandigarh","DD":"Daman & Diu","DL":"Delhi",
    "DN":"Dadra & Nagar Haveli","GA":"Goa","GJ":"Gujarat","HP":"Himachal Pradesh",
    "HR":"Haryana","JH":"Jharkhand","JK":"Jammu & Kashmir","KA":"Karnataka","KL":"Kerala",
    "LA":"Ladakh","LD":"Lakshadweep","MH":"Maharashtra","ML":"Meghalaya","MN":"Manipur",
    "MP":"Madhya Pradesh","MZ":"Mizoram","NL":"Nagaland","OD":"Odisha","PB":"Punjab",
    "PY":"Puducherry","RJ":"Rajasthan","SK":"Sikkim","TN":"Tamil Nadu","TR":"Tripura",
    "TS":"Telangana","UK":"Uttarakhand","UP":"Uttar Pradesh","WB":"West Bengal",
}

def lookup_vehicle(plate: str) -> dict:
    plate = plate.strip().upper().replace(" ", "").replace("-", "")
    if len(plate) < 6:
        return {"status": "error", "message": "Enter a valid Indian plate e.g. DL01AB1234"}
    state = STATE_CODES.get(plate[:2], "Unknown State")
    return {"status": "success", "plate": plate, "state_code": plate[:2],
            "state": state, "rto_code": plate[:4],
            "links": [
                {"label": "RC Details — CarInfo",     "url": f"https://www.carinfo.app/rc-search/{plate}"},
                {"label": "E-Challan — Parivahan",    "url": "https://echallan.parivahan.gov.in/index/accused-challan"},
                {"label": "RC Status — Vahan",        "url": "https://vahan.parivahan.gov.in/vahanservice/vahan/ui/statevalidation/homepage.xhtml"},
            ],
            "note": "Click a link to check full RC details and challans."}


# ─── GitHub Deep Profile ──────────────────────────────────────────────────────
def lookup_github(username: str) -> dict:
    username = username.strip()
    try:
        user_r = requests.get(f"https://api.github.com/users/{username}",
                              headers={"Accept": "application/vnd.github+json"}, timeout=8)
        if user_r.status_code == 404:
            return {"status": "error", "message": f"GitHub user '{username}' not found"}
        if user_r.status_code != 200:
            return {"status": "error", "message": f"GitHub API returned {user_r.status_code}"}
        u = user_r.json()

        repos_r = requests.get(f"https://api.github.com/users/{username}/repos",
                               params={"per_page": 100, "sort": "updated"},
                               headers={"Accept": "application/vnd.github+json"}, timeout=8)
        repos = repos_r.json() if repos_r.status_code == 200 else []

        # Extract commit emails from recent events
        events_r = requests.get(f"https://api.github.com/users/{username}/events/public",
                                params={"per_page": 100},
                                headers={"Accept": "application/vnd.github+json"}, timeout=8)
        emails = set()
        if events_r.status_code == 200:
            for event in events_r.json():
                if event.get("type") == "PushEvent":
                    for commit in event.get("payload", {}).get("commits", []):
                        email = commit.get("author", {}).get("email", "")
                        if email and "noreply" not in email:
                            emails.add(email)

        top_repos = [{"name": r["name"], "stars": r["stargazers_count"],
                      "language": r["language"], "url": r["html_url"],
                      "description": r.get("description", "")}
                     for r in sorted(repos, key=lambda x: x["stargazers_count"], reverse=True)[:10]]

        languages = {}
        for r in repos:
            if r.get("language"):
                languages[r["language"]] = languages.get(r["language"], 0) + 1
        top_langs = sorted(languages.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "status": "success",
            "username": u.get("login"),
            "name": u.get("name"),
            "bio": u.get("bio"),
            "location": u.get("location"),
            "email": u.get("email"),
            "company": u.get("company"),
            "blog": u.get("blog"),
            "twitter": u.get("twitter_username"),
            "avatar": u.get("avatar_url"),
            "profile_url": u.get("html_url"),
            "created_at": u.get("created_at"),
            "public_repos": u.get("public_repos", 0),
            "followers": u.get("followers", 0),
            "following": u.get("following", 0),
            "top_repos": top_repos,
            "top_languages": [{"lang": l, "count": c} for l, c in top_langs],
            "commit_emails": list(emails),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── Reddit Activity ──────────────────────────────────────────────────────────
def lookup_reddit(username: str) -> dict:
    username = username.strip()
    headers = {"User-Agent": "osint-profiler/1.0"}
    try:
        about_r = requests.get(f"https://www.reddit.com/user/{username}/about.json",
                               headers=headers, timeout=8)
        if about_r.status_code == 404:
            return {"status": "error", "message": f"Reddit user '{username}' not found"}
        if about_r.status_code != 200:
            return {"status": "error", "message": f"Reddit API returned {about_r.status_code}"}
        about = about_r.json().get("data", {})

        posts_r = requests.get(f"https://www.reddit.com/user/{username}/submitted.json",
                               params={"limit": 25}, headers=headers, timeout=8)
        comments_r = requests.get(f"https://www.reddit.com/user/{username}/comments.json",
                                  params={"limit": 25}, headers=headers, timeout=8)

        posts = []
        subreddits = {}
        if posts_r.status_code == 200:
            for p in posts_r.json().get("data", {}).get("children", []):
                d = p["data"]
                sub = d.get("subreddit", "")
                subreddits[sub] = subreddits.get(sub, 0) + 1
                posts.append({"title": d.get("title"), "subreddit": sub,
                               "score": d.get("score", 0), "url": f"https://reddit.com{d.get('permalink','')}"})

        comments = []
        if comments_r.status_code == 200:
            for c in comments_r.json().get("data", {}).get("children", []):
                d = c["data"]
                sub = d.get("subreddit", "")
                subreddits[sub] = subreddits.get(sub, 0) + 1
                comments.append({"body": d.get("body", "")[:200], "subreddit": sub,
                                  "score": d.get("score", 0), "url": f"https://reddit.com{d.get('permalink','')}"})

        top_subs = sorted(subreddits.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "status": "success",
            "username": about.get("name"),
            "karma_post": about.get("link_karma", 0),
            "karma_comment": about.get("comment_karma", 0),
            "created_utc": about.get("created_utc"),
            "is_mod": about.get("is_mod", False),
            "profile_url": f"https://www.reddit.com/user/{username}",
            "top_subreddits": [{"name": s, "count": c} for s, c in top_subs],
            "recent_posts": posts[:10],
            "recent_comments": comments[:10],
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── Domain / IP OSINT ───────────────────────────────────────────────────────
def lookup_domain(query: str) -> dict:
    query = query.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    result = {"status": "success", "query": query}

    # Resolve IP
    try:
        ip = socket.gethostbyname(query)
        result["ip"] = ip
    except Exception:
        ip = None
        result["ip"] = None

    # DNS records via public DoH (Cloudflare)
    dns_types = {"A": 1, "MX": 15, "TXT": 16, "NS": 2, "CNAME": 5}
    dns_records = {}
    for rtype, rnum in dns_types.items():
        try:
            r = requests.get("https://cloudflare-dns.com/dns-query",
                             params={"name": query, "type": rtype},
                             headers={"Accept": "application/dns-json"}, timeout=6)
            if r.status_code == 200:
                answers = r.json().get("Answer", [])
                dns_records[rtype] = [a.get("data", "") for a in answers]
        except Exception:
            pass
    result["dns"] = dns_records

    # IP info (ip-api.com — free, no key)
    target = ip if ip else query
    try:
        ip_r = requests.get(f"http://ip-api.com/json/{target}",
                            params={"fields": "status,country,regionName,city,isp,org,as,lat,lon,reverse,proxy,hosting"},
                            timeout=6)
        if ip_r.status_code == 200:
            d = ip_r.json()
            if d.get("status") == "success":
                result["ip_info"] = {
                    "country": d.get("country"), "region": d.get("regionName"),
                    "city": d.get("city"), "isp": d.get("isp"), "org": d.get("org"),
                    "asn": d.get("as"), "lat": d.get("lat"), "lon": d.get("lon"),
                    "reverse_dns": d.get("reverse"), "is_proxy": d.get("proxy"),
                    "is_hosting": d.get("hosting"),
                }
    except Exception:
        pass

    # WHOIS via whoisjson.com (free, no key)
    try:
        w = requests.get(f"https://whoisjson.com/api/v1/whois?domain={query}", timeout=8)
        if w.status_code == 200:
            wd = w.json()
            result["whois"] = {
                "registrar": wd.get("registrar"),
                "created": wd.get("creation_date"),
                "expires": wd.get("expiration_date"),
                "updated": wd.get("updated_date"),
                "name_servers": wd.get("name_servers", []),
                "status": wd.get("status", []),
            }
    except Exception:
        pass

    # Useful links
    result["links"] = [
        {"label": "Shodan",          "url": f"https://www.shodan.io/search?query={query}"},
        {"label": "VirusTotal",      "url": f"https://www.virustotal.com/gui/domain/{query}"},
        {"label": "URLScan.io",      "url": f"https://urlscan.io/search/#{query}"},
        {"label": "Censys",          "url": f"https://search.censys.io/hosts/{ip or query}"},
        {"label": "SecurityTrails",  "url": f"https://securitytrails.com/domain/{query}/dns"},
        {"label": "DNSDumpster",     "url": f"https://dnsdumpster.com/"},
    ]

    return result


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

@app.route("/api/github", methods=["POST"])
def api_github():
    data = request.get_json()
    if not data or not data.get("username"):
        return jsonify({"error": "username required"}), 400
    return jsonify(lookup_github(data["username"]))

@app.route("/api/reddit", methods=["POST"])
def api_reddit():
    data = request.get_json()
    if not data or not data.get("username"):
        return jsonify({"error": "username required"}), 400
    return jsonify(lookup_reddit(data["username"]))

@app.route("/api/domain", methods=["POST"])
def api_domain():
    data = request.get_json()
    if not data or not data.get("query"):
        return jsonify({"error": "query required"}), 400
    return jsonify(lookup_domain(data["query"]))

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok",
                    "veriphone_configured": bool(VERIPHONE_KEY),
                    "emailrep_configured": bool(EMAILREP_KEY)})

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.getenv("PORT", 5001)))
