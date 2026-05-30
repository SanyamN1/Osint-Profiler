# OSINT People Profiler

A web-based open-source intelligence tool for researching people using freely available internet data.

## Modules

| Module | What it does | API Required |
|---|---|---|
| **Username Checker** | Checks 20+ platforms (GitHub, Instagram, Twitter, TikTok, Reddit, etc.) to see if a username is taken or available | No |
| **Phone Lookup** | Returns carrier, country, location, and line type for any phone number | NumVerify (opt) |
| **Email Breach Check** | Checks if an email appears in known data breaches and paste sites via HaveIBeenPwned | HIBP v3 |
| **Name Search** | Generates direct people-search links across LinkedIn, Facebook, Twitter, Google, TikTok, GitHub, Reddit, Pipl, Spokeo, and BeenVerified | No |

## Setup

### 1. Clone & install

```bash
git clone https://github.com/SanyamN1/Osint-Profiler
cd Osint-Profiler
pip install -r requirements.txt
```

### 2. Configure API keys (optional)

```bash
export HIBP_API_KEY="your_hibp_key"          # haveibeenpwned.com — $3.50/month
export NUMVERIFY_API_KEY="your_numverify_key" # numverify.com — free tier available
```

Without keys, username checking and name search work fully. Phone lookup returns basic info. Email breach check requires HIBP.

**Get API keys:**
- HIBP: https://haveibeenpwned.com/API/Key
- NumVerify: https://numverify.com (free tier: 100 req/month)

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

### `POST /api/username`
```json
{ "username": "johndoe" }
```
Returns `found` (platforms where username is taken) and `not_found` arrays.

### `POST /api/phone`
```json
{ "number": "+15550001234" }
```
Returns carrier, country, location, line type.

### `POST /api/email`
```json
{ "email": "user@example.com" }
```
Returns breach list with dates, affected data types, and paste site appearances.

### `POST /api/name`
```json
{ "name": "John Doe" }
```
Returns direct search links for the name across 11 platforms.

### `GET /api/health`
Returns API key configuration status.

## Tech Stack

- **Backend**: Python, Flask, concurrent.futures
- **Frontend**: Vanilla JS, CSS Grid (no framework)
- **Deployment**: Vercel Python serverless

## Legal

This tool only uses publicly available data and official APIs. Use responsibly and in accordance with applicable laws. Do not use for stalking, harassment, or any illegal purpose.
