# Albireo 🛡️
**Albireo** is a **serverless Proof-of-Work (PoW) protection** for static websites on **Cloudflare Pages**, based on [Anubis](https://github.com/TecharoHQ/anubis).  
Albireo is designed to **deter the vast majority of automated crawlers**, including bots scraping your static content, without requiring a traditional server.  
It is **not intended to defeat highly resourced or targeted scraping operations**.

[DEMO（My blog)](https://www.leaftechblog.cloudns.biz/)
---

## Why Albireo?
Many static sites (GitHub Pages, Netlify, Vercel) **cannot run traditional anti-crawler systems** like Anubis, which require a server or reverse proxy.  
(Now support Cloudflare Pages, Netlify, and Vercel)

Albireo allows you to:
- ✅ Protect your static content with PoW challenges  
- ✅ Fully serverless: runs on Cloudflare Pages Functions / Netlify Edge Functions  
- ✅ Customizable front-end: mascots, messages, and UI  
- ✅ Configurable difficulty: adjust CPU cost per request  
- ✅ SEO-friendly: whitelist search engine bots  
- ✅ Multi-threaded PoW: uses Web Workers to parallelize computation  
- ✅ Challenge expiry: prevents stale challenges from being reused  
- ✅ Safe redirect: prevents open redirect attacks after verification  

> Perfect for static documentation sites, portfolios, or open-source projects that want lightweight anti-scraping protection.

---

## How does Albireo compare?

| | Albireo | Anubis | Cloudflare Free | Cloudflare Pro+ |
|---|---|---|---|---|
| Cost | **Free** | Free | Free | $20–200+/mo |
| Requires server | ❌ | ✅ | ❌ | ❌ |
| Works on Netlify | ✅ | ❌ | ❌ | ❌ |
| Works on Vercel | ✅ | ❌ | ❌ | ❌ |
| Proof-of-Work | ✅ | ✅ | ❌ | ✅ |
| Blocks JS-less bots | ✅ | ✅ | ⚠️ partial | ✅ |
| Slows headless browsers | ✅ | ✅ | ❌ | ✅ |
| Open source | ✅ | ✅ | ❌ | ❌ |
| Dynamic difficulty | ❌ | ✅ | ❌ | ✅ |

> Cloudflare's free Bot Fight Mode relies on User-Agent and IP heuristics, which are easy to bypass. Albireo's PoW forces every client — including headless browsers — to perform real computation, making large-scale scraping expensive even for bots that can run JavaScript.

---

## Setup (Cloudflare Pages)
1. Copy the `functions` folder to your Cloudflare Pages project  
2. Change `SECRET_KEY` in `_middleware.ts`  
3. Add Images: Create `public/anubis-dist/img/` and add your own:  
   - `pensive.webp`  
   - `happy.webp`  
   - `reject.webp`  

> If you don't have images, the security check page will automatically fall back to emoji indicators (😐 / 😊 / ❌), so the protection works out of the box without any setup.

## Setup (Netlify)
Use this if your site is hosted on Netlify.

1. **Copy Files**: Go to the `For_Netlify` folder in this repo, and copy all its contents (`netlify/`, `netlify.toml`) to the root of your own project.  
   - Your project root should now have a `netlify.toml` file and a `netlify` folder.  
2. **Configure Secret**:  
   - Open `netlify/edge-functions/albireo.ts`.  
   - Find `SECRET_KEY` and change it to a random string (**Security Requirement**).  
3. **Add Images**:  
   - Create a folder `public/anubis-dist/img/` in your project (or ensure `public` exists).  
   - Add your mascot images: `pensive.webp`, `happy.webp`, `reject.webp`.  
   > If you don't have images, the security check page will automatically fall back to emoji indicators (😐 / 😊 / ❌), so the protection works out of the box without any setup.
4. **Deploy**: Push to your repository. Netlify will automatically detect the Edge Functions via `netlify.toml`.

## Setup (Vercel)
Use this if your site is hosted on Vercel (Next.js or other frameworks).
Go to "For Vercel" folder
1. **Copy File**: Copy `middleware.ts` to the **root of your project**.
2. **Configure Secret**:
   - Open `middleware.ts`.
   - Find `SECRET_KEY` and change it to a random string (**Security Requirement**).
3. **Add Images**:
   - Create a folder `public/anubis-dist/img/` in your project.
   - Add your mascot images: `pensive.webp`, `happy.webp`, `reject.webp`.
   > If you don't have images, the security check page will automatically fall back to emoji indicators (😐 / 😊 / ❌), so the protection works out of the box without any setup.
4. **Deploy**: Push to your repository. Vercel will automatically pick up `middleware.ts`.

---

## Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `DIFFICULTY` | PoW difficulty (higher = more CPU cost). Recommended: 3–6 | `5` |
| `SECRET_KEY` | HMAC signing key. **Must be changed before deployment** | — |
| `BOT_AGENTS` | List of user agent substrings to whitelist (SEO bots) | Google, Bing, Yahoo, DuckDuckBot |
| `CHALLENGE_TTL` | How long a challenge is valid (milliseconds) | `300000` (5 min) |
| `STRINGS` | UI text for all labels and button states (for localization) | English |

### Localization example
To display the security check in Traditional Chinese, change the `STRINGS` object in the config:
```ts
const STRINGS = {
  title: "安全驗證 | Albireo",
  heading: "安全驗證",
  description: "請確認您是真人。",
  btn_start: "我是人類",
  btn_calculating: "計算中...",
  btn_verifying: "驗證中...",
  btn_success: "成功！",
  btn_retry: "重試",
  btn_error: "錯誤",
};
```

# 等待翻譯
目前在CF page新增Honeypot邏輯
---

## License
MIT (Based on [Anubis](https://github.com/TecharoHQ/anubis) by TecharoHQ)

[Why I'm using Albireo not Cloudflare?](https://www.leaftechblog.cloudns.biz/2026/01/26/Myblog/)
