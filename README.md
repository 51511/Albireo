# Albireo 🛡️

**Albireo** is a serverless Proof-of-Work (PoW) protection for Cloudflare Pages, based on Anubis.
Albireo is designed to deter the vast majority of automated crawlers on the web.
It is not intended to defeat highly resourced or targeted scraping operations.

## Setup

1. Copy \`functions\` folder to your project.
2. Change \`SECRET_KEY\` in \`_middleware.ts\`.
3. **Add Images**: Create \`public/anubis-dist/img/\` and add your own \`pensive.webp\`, \`happy.webp\`, and \`reject.webp\`.

## License
MIT (Based on Anubis by TecharoHQ).
