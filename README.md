# Albireo 🛡️

**Albireo** is a **serverless Proof-of-Work (PoW) protection** for static websites, based on [Anubis](https://github.com/TecharoHQ/anubis).  
Albireo is designed to **deter the vast majority of automated crawlers**, including bots scraping your static content, without requiring a traditional server.  
It is **not intended to defeat highly resourced or targeted scraping operations**.

[DEMO (My blog)](https://www.leaftechblog.cloudns.biz/)

---

## Why Albireo?

Many static sites (GitHub Pages, Netlify, Vercel) **cannot run traditional anti-crawler systems** like Anubis, which require a server or reverse proxy.

Albireo allows you to:
- ✅ Protect your static content with PoW challenges
- ✅ Fully serverless: runs on Cloudflare Pages Functions / Netlify Edge Functions / Vercel Middleware
- ✅ Suspicion scoring: blocks known crawler UA, missing headers before PoW is even issued
- ✅ Honeypot trap: silently marks and blocks crawlers that follow hidden links
- ✅ Bot behavior detection: uses [BotD](https://github.com/fingerprintjs/BotD) to detect headless browsers before PoW
- ✅ Customizable front-end: mascots, messages, and UI
- ✅ Configurable difficulty: adjust CPU cost per request
- ✅ SEO-friendly: whitelist search engine bots (always bypasses scoring)
- ✅ Multi-threaded PoW: uses Web Workers to parallelize computation
- ✅ Challenge expiry: prevents stale challenges from being reused
- ✅ Safe redirect: prevents open redirect attacks after verification

**Cloudflare Pages only (v2):**
- ✅ Silent browser fingerprinting: 9-signal scoring detects headless browsers before any challenge is shown
- ✅ Human fast-pass: real users pass silently with difficulty=1 PoW, no challenge page shown at all
- ✅ HMAC-signed solved cookie: prevents forging the solved state with a plain cookie
- ✅ Auto-execute on page load: no "I am human" button, everything runs automatically

> Perfect for static documentation sites, portfolios, or open-source projects that want lightweight anti-scraping protection.

---

## How does Albireo compare?

| | Albireo (CF v2) | Albireo | Anubis | Cloudflare Free | Cloudflare Pro+ |
|---|---|---|---|---|---|
| Cost | **Free** | **Free** | Free | Free | $20–200+/mo |
| Requires server | ❌ | ❌ | ✅ | ❌ | ❌ |
| Works on Netlify | ❌ (v2) | ✅ | ❌ | ❌ | ❌ |
| Works on Vercel | ❌ (v2) | ✅ | ❌ | ❌ | ❌ |
| Proof-of-Work | ✅ | ✅ | ✅ | ❌ | ✅ |
| Suspicion scoring | ✅ | ✅ | ✅ | ❌ | ✅ |
| Honeypot trap | ✅ | ✅ | ✅ | ❌ | ✅ |
| Bot behavior detection | ✅ | ✅ | ❌ | ⚠️ partial | ✅ |
| Browser fingerprinting | ✅ | ❌ | ❌ | ❌ | ⚠️ partial |
| Human fast-pass (no challenge) | ✅ | ❌ | ❌ | ❌ | ❌ |
| HMAC-signed cookies | ✅ | ❌ | ✅ | — | — |
| Blocks JS-less bots | ✅ | ✅ | ✅ | ⚠️ partial | ✅ |
| Slows headless browsers | ✅ | ✅ | ✅ | ❌ | ✅ |
| Open source | ✅ | ✅ | ✅ | ❌ | ❌ |
| Dynamic difficulty | ❌ | ❌ | ✅ | ❌ | ✅ |

> Cloudflare's free Bot Fight Mode relies on User-Agent and IP heuristics, which are easy to bypass. Albireo's PoW forces every client — including headless browsers — to perform real computation, making large-scale scraping expensive even for bots that can run JavaScript.

---

## How it works (Cloudflare Pages v2)

When a visitor arrives, Albireo runs five layers of protection in order:

```
0. SEO bot whitelist (BOT_AGENTS)
   Google, Bing, Yahoo, DuckDuckBot and any custom entries → pass through immediately.
   Whitelisted bots skip ALL checks below.

1. Suspicion scoring (server-side)
   Each request is scored before any challenge is issued:
   · UA contains bot/crawler/spider/scrapy/curl/wget/...  → +10
   · No Accept header                                     → +5
   · No User-Agent at all                                 → +10
   score >= 10 → 403 immediately, no challenge issued.
   score <  10 → continue to next layer.

2. Honeypot
   Every HTML page (including the challenge page) contains a hidden link
   invisible to humans but followed by crawlers.
   → Crawler visits trap URL: sets albireo_bot cookie (24hr) → 403.
   → Subsequent requests from marked crawlers: always 403.

3. Silent browser fingerprinting (client-side, NEW in v2)
   9 signals scored silently on page load, no user interaction needed:
   · navigator.webdriver === true          → +100 (direct automation flag)
   · WebGL SwiftShader / llvmpipe renderer → +60  (headless software renderer)
   · CDP artifacts in window object        → +80  (ChromeDriver leftovers)
   · navigator.plugins empty or fake       → +25/+40
   · Chrome UA but no window.chrome        → +30
   · navigator.languages missing           → +20
   · Canvas renders blank                  → +35
   · screen size zero or abnormal          → +20/+40
   · Notification permission anomaly       → +15

   score >= 60 → Access Denied immediately, no PoW issued.
   score < 10  → Human fast-pass: silent difficulty=1 PoW, user sees nothing. ✨
   score 10–59 → Continue to BotD + full PoW.

4. BotD (client-side)
   Detects headless browsers (Puppeteer, Playwright, Selenium) before PoW starts.
   → Detected bot: blocked immediately, no PoW issued.
   → Load failure (e.g. adblocker): falls through to PoW silently.

5. Proof-of-Work (SHA-256)
   The browser must find a nonce whose SHA-256 hash starts with N leading zeroes.
   Parallelized across CPU cores via Web Workers.
   → Passed: sets HMAC-signed albireo_solved cookie (24hr).
   → Cookie is verified server-side on every subsequent request.
```

### Human fast-pass flow (v2)

Real browsers with no suspicious signals skip the challenge entirely:

```
Page loads → fingerprint score = 0 → silent difficulty=1 PoW (~100ms)
→ HMAC-signed cookie issued → redirect to destination
User sees: nothing. Total time: ~300ms.
```

---

## Setup (Cloudflare Pages)

1. Copy the `functions` folder to your Cloudflare Pages project
2. Change `SECRET_KEY` in `functions/_middleware.ts`
3. Add images: create `public/albireo-dist/img/` and add:
   - `pensive.webp`
   - `happy.webp`
   - `reject.webp`

> If you don't have images, the security check page automatically falls back to emoji indicators (😐 / 😊 / ❌).

## Setup (Netlify)

1. **Copy Files**: Copy all contents of `For_Netlify/` (`netlify/`, `netlify.toml`) to the root of your project
2. **Configure Secret**: Open `netlify/edge-functions/albireo.ts`, find `SECRET_KEY` and change it to a random string
3. **Add Images**: Create `public/albireo-dist/img/` and add `pensive.webp`, `happy.webp`, `reject.webp`
4. **Deploy**: Push to your repository. Netlify will detect the Edge Functions via `netlify.toml`

> If you don't have images, the security check page automatically falls back to emoji indicators (😐 / 😊 / ❌).

> ⚠️ **Netlify/Vercel note**: The fingerprinting, fast-pass, and HMAC cookie features are **Cloudflare Pages only (v2)**. Netlify and Vercel versions remain at v1 behaviour.

## Setup (Vercel)

1. **Copy File**: Copy `For_Vercel/middleware.ts` to the **root of your project**
2. **Configure Secret**: Open `middleware.ts`, find `SECRET_KEY` and change it to a random string
3. **Add Images**: Create `public/albireo-dist/img/` and add `pensive.webp`, `happy.webp`, `reject.webp`
4. **Deploy**: Push to your repository. Vercel will automatically pick up `middleware.ts`

> If you don't have images, the security check page automatically falls back to emoji indicators (😐 / 😊 / ❌).

> ⚠️ **Vercel limitation**: Honeypot link injection is not supported on Vercel because Next.js Middleware cannot modify response bodies. The honeypot trap path detection still works — crawlers that somehow visit `/albireo-trap-*` will still be marked. For full honeypot support, use Cloudflare Pages or Netlify.

---

## Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `DIFFICULTY` | PoW difficulty (higher = more CPU cost). Recommended: 3–6 | `3–5` |
| `SECRET_KEY` | HMAC signing key. **Must be changed before deployment** | — |
| `BOT_AGENTS` | User agent substrings to whitelist (SEO bots, always bypass scoring) | Google, Bing, Yahoo, DuckDuckBot |
| `BOT_UA_PATTERNS` | UA substrings that add +10 suspicion score | bot, crawler, scrapy, curl, wget, ... |
| `CHALLENGE_TTL` | How long a challenge is valid (milliseconds) | `300000` (5 min) |
| `HONEYPOT_TTL` | How long a honeypot token is valid (milliseconds) | `3600000` (1 hr) |
| `STRINGS` | UI text for all labels and button states (localization) | English |

### Localization example

To display the security check in Traditional Chinese:

```ts
const STRINGS = {
  title: "安全驗證 | Albireo",
  heading: "安全驗證",
  description: "請確認您是真人。",
  btn_start: "我是人類",
  btn_checking: "偵測中...",
  btn_calculating: "計算中...",
  btn_verifying: "驗證中...",
  btn_success: "成功！",
  btn_retry: "重試",
  btn_error: "錯誤",
  btn_bot_detected: "存取遭拒",
};
```

---

## License

MIT (Based on [Anubis](https://github.com/TecharoHQ/anubis) by TecharoHQ)

[Why I'm using Albireo not Cloudflare?](https://www.leaftechblog.cloudns.biz/2026/01/26/Myblog/)
