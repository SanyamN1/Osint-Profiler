# OSINT Investigation Framework

A Python-based automated intelligence gathering tool for threat actor profiling, domain investigation, and digital forensics workflows.

## Modules

| Module | Description | API Required |
|--------|-------------|--------------|
| **WHOIS** | Registrar, creation date, nameservers, contacts | No |
| **DNS** | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA records + SPF/DMARC | No |
| **IP Intel** | Geolocation, ASN, open ports, CVEs via Shodan | IPInfo (opt), Shodan (opt) |
| **Tech Stack** | Server, CMS, CDN, frameworks via header analysis | No |
| **Email Intel** | Employee email addresses, formats, confidence scores | Hunter.io |
| **Reputation** | VirusTotal domain scoring + threat categories | VirusTotal |

## Use Cases

- Threat actor profiling during incident response
- Pre-engagement reconnaissance in penetration testing
- Phishing infrastructure investigation
- Digital forensics and IOC enrichment
- OSINT-led security research

## Setup

### 1. Clone & install
```bash
git clone https://github.com/YOUR_USERNAME/osint-framework
cd osint-framework
pip install -r requirements.txt
```

### 2. Configure API keys (optional but recommended)
```bash
export HUNTER_API_KEY="your_hunter_key"
export SHODAN_API_KEY="your_shodan_key"
export IPINFO_TOKEN="your_ipinfo_token"
export VIRUSTOTAL_API_KEY="your_vt_key"
```

**Free API keys:**
- Hunter.io: https://hunter.io (25 req/month free)
- Shodan: https://account.shodan.io (free tier available)
- IPInfo: https://ipinfo.io (50,000 req/month free)
- VirusTotal: https://www.virustotal.com/gui/join-us (500 req/day free)

### 3. Run locally
```bash
python app.py
# Open http://localhost:5001
```

## Deploy to Vercel

```bash
npm i -g vercel
vercel --prod
```

Add environment variables in Vercel dashboard → Project → Settings → Environment Variables.

## API Reference

### `POST /api/investigate`
```json
{
  "target": "example.com",
  "modules": ["whois", "dns", "ip", "tech", "email", "reputation"]
}
```

Runs selected modules in parallel and returns combined intelligence report.

### `GET /api/health`
Returns API key configuration status for all integrations.

## Tech Stack

- **Backend**: Python, Flask, concurrent.futures (parallel module execution)
- **DNS**: dnspython
- **WHOIS**: python-whois
- **APIs**: Hunter.io v2, Shodan REST, IPInfo, VirusTotal v3
- **Frontend**: Vanilla JS, CSS Grid (no framework)
- **Deployment**: Vercel Python serverless
