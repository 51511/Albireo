# Albireo 🛡️

**Albireo** is a **serverless Proof-of-Work (PoW) protection** for static websites on **Cloudflare Pages**, based on [Anubis](https://github.com/TecharoHQ/anubis).  

Albireo is designed to **deter the vast majority of automated crawlers**, including bots scraping your static content, without requiring a traditional server.  
It is **not intended to defeat highly resourced or targeted scraping operations**.

---

## Why Albireo?

Many static sites (GitHub Pages, Netlify, Vercel) **cannot run traditional anti-crawler systems** like Anubis, which require a server or reverse proxy.  

Albireo allows you to:

- ✅ Protect your static content with PoW challenges  
- ✅ Fully serverless: runs on Cloudflare Pages Functions  
- ✅ Customizable front-end: mascots, messages, and UI  
- ✅ Configurable difficulty: adjust CPU cost per request  
- ✅ SEO-friendly: whitelist search engine bots  

> Perfect for static documentation sites, portfolios, or open-source projects that want lightweight anti-scraping protection.

---

## Setup

1. Copy the `functions` folder to your Cloudflare Pages project  
2. Change `SECRET_KEY` in `_middleware.ts`  
3. Add Images: Create `public/anubis-dist/img/` and add your own:  
   - `pensive.webp`  
   - `happy.webp`  
   - `reject.webp`  

---

## Configuration

- **Difficulty**: Adjust `DIFFICULTY` to control PoW cost  
- **SEO Whitelist**: Add bot user agents in `BOT_AGENTS`  
- **Secret Key**: Must change `SECRET_KEY` before deployment

---

## License

MIT (Based on Anubis by TecharoHQ)
