interface Env {
  ASSETS: Fetcher;
}

// === Configuration ===
const DIFFICULTY = 3;
const SECRET_KEY = "ALBIREO_SECRET_KEY_CHANGE_ME"; // ★ 請務必修改這裡
const BOT_AGENTS = ["google", "bingbot", "yahoo", "duckduckbot"];
const CHALLENGE_TTL = 5 * 60 * 1000;
const HONEYPOT_TTL = 60 * 60 * 1000;
const HONEYPOT_PREFIX = "/albireo-trap-";

// === UI Strings ===
const STRINGS = {
  title: "Security Check | Albireo",
  heading: "Security Check",
  description: "Please verify you are human.",
  btn_start: "I am human",
  btn_checking: "Checking...",
  btn_calculating: "Calculating...",
  btn_verifying: "Verifying...",
  btn_success: "Success!",
  btn_retry: "Retry",
  btn_error: "Error",
  btn_bot_detected: "Access Denied",
};

// === Crypto Utils ===
async function sign(msg: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(SECRET_KEY),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function verify(msg: string, sig: string): Promise<boolean> {
  const expected = await sign(msg);
  return expected === sig;
}

async function checkPoW(
  challenge: string, nonce: string, response: string, difficulty: number
): Promise<boolean> {
  const msg = challenge + String(nonce);
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(msg));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const calculated = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  if (calculated !== response) return false;
  return calculated.startsWith("0".repeat(difficulty));
}

// === Honeypot Utils ===
async function generateHoneypotToken(): Promise<string> {
  const timestamp = Date.now().toString();
  const sig = await sign("honeypot." + timestamp);
  const safeSig = sig.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return timestamp + "." + safeSig;
}

async function verifyHoneypotToken(token: string): Promise<boolean> {
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [timestamp, safeSig] = parts;
  let sig = safeSig.replace(/-/g, '+').replace(/_/g, '/');
  while (sig.length % 4 !== 0) sig += '=';
  const issuedAt = parseInt(timestamp, 10);
  if (isNaN(issuedAt)) return false;
  if (Date.now() - issuedAt > HONEYPOT_TTL) return false;
  return await verify("honeypot." + timestamp, sig);
}

// === Safe Redirect ===
function safeRedirect(path: string): string {
  try {
    if (path.startsWith('/') && !path.startsWith('//')) return path;
  } catch (_) {}
  return '/';
}

// === HTML Generator ===
// FIX: 移除 fast_pass，改由 server 決定難度並傳給 client
const GENERATE_HTML = (challenge: string, originalPath: string, powDifficulty: number) => `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<title>${STRINGS.title}</title>
<style>
:root { --primary: #00ad9f; --bg: #f4f6f8; --card: #ffffff; --text: #2d3748; }
@media (prefers-color-scheme: dark) { :root { --bg: #121212; --card: #1e1e1e; --text: #ffffff; } }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
.box { background: var(--card); padding: 40px; border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 100%; }
.mascot { width: 120px; height: 120px; border-radius: 50%; object-fit: cover; border: 4px solid var(--card); box-shadow: 0 0 0 4px var(--primary); margin-bottom: 20px; }
.mascot-emoji { font-size: 80px; line-height: 1; margin-bottom: 20px; display: none; }
h1 { margin-bottom: 10px; }
#status { margin-top: 16px; font-size: 0.9rem; color: #888; min-height: 24px; }
#progress-bar { display: none; height: 4px; background: #e2e8f0; border-radius: 2px; margin-top: 12px; overflow: hidden; }
#progress-fill { height: 100%; width: 0%; background: var(--primary); border-radius: 2px; transition: width 0.3s ease; animation: indeterminate 1.5s ease-in-out infinite; }
@keyframes indeterminate {
  0% { width: 0%; margin-left: 0%; }
  50% { width: 60%; margin-left: 20%; }
  100% { width: 0%; margin-left: 100%; }
}
#denied-msg { display: none; margin-top: 16px; padding: 12px; background: #fff5f5; border-radius: 8px; color: #c53030; font-size: 0.9rem; }
</style>
</head>
<body>
<div class="box">
  <img src="/albireo-dist/img/pensive.webp" class="mascot" id="mascot-img" alt="Guard"
    onerror="this.style.display='none'; document.getElementById('mascot-emoji').style.display='block';">
  <div class="mascot-emoji" id="mascot-emoji">😐</div>
  <h1>${STRINGS.heading}</h1>
  <p id="desc">${STRINGS.description}</p>
  <div id="status"></div>
  <div id="progress-bar"><div id="progress-fill"></div></div>
  <div id="denied-msg">${STRINGS.btn_bot_detected}</div>
</div>
<script>
const CHALLENGE = "${challenge}";
// FIX: 難度由 server 決定並嵌入 HTML，client 無法竄改
const DIFFICULTY = ${powDifficulty};
const ORIGINAL_PATH = "${originalPath}";
const IMG_PASS  = "/albireo-dist/img/pensive.webp";
const IMG_OK    = "/albireo-dist/img/happy.webp";
const IMG_FAIL  = "/albireo-dist/img/reject.webp";
const EMOJI_PASS = "😐";
const EMOJI_OK   = "😊";
const EMOJI_FAIL = "❌";

const img      = document.getElementById('mascot-img');
const emoji    = document.getElementById('mascot-emoji');
const status   = document.getElementById('status');
const progress = document.getElementById('progress-bar');
const denied   = document.getElementById('denied-msg');
const desc     = document.getElementById('desc');

const usingEmoji = () => img.style.display === 'none';
function setMascot(imgSrc, emojiChar) {
  if (usingEmoji()) emoji.innerText = emojiChar;
  else img.src = imgSrc;
}
function setStatus(msg) { status.innerText = msg; }
function showProgress() { progress.style.display = 'block'; }
function hideProgress() { progress.style.display = 'none'; }
function showDenied() {
  denied.style.display = 'block';
  desc.style.display = 'none';
}

// === PoW Web Worker ===
const WORKER_CODE = \`
async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}
self.onmessage = async (e) => {
  const { challenge, difficulty, startNonce, step } = e.data;
  const prefix = "0".repeat(difficulty);
  let nonce = startNonce;
  while (true) {
    const hash = await sha256(challenge + nonce);
    if (hash.startsWith(prefix)) { self.postMessage({ found: true, nonce, hash }); return; }
    nonce += step;
  }
};
\`;

function createWorker() {
  const blob = new Blob([WORKER_CODE], { type: 'application/javascript' });
  return new Worker(URL.createObjectURL(blob));
}

function mine() {
  setStatus(${JSON.stringify(STRINGS.btn_calculating)});
  showProgress();
  const numWorkers = Math.max(1, (navigator.hardwareConcurrency || 4) - 1);
  const workers = [];
  let done = false;
  for (let i = 0; i < numWorkers; i++) {
    const worker = createWorker();
    workers.push(worker);
    // FIX: 使用 server 決定的 DIFFICULTY，不再有 fast_pass 參數
    worker.postMessage({ challenge: CHALLENGE, difficulty: DIFFICULTY, startNonce: i, step: numWorkers });
    worker.onmessage = (e) => {
      if (done) return;
      done = true;
      workers.forEach(w => w.terminate());
      submit(e.data.nonce, e.data.hash);
    };
  }
}

function submit(nonce, response) {
  setStatus(${JSON.stringify(STRINGS.btn_verifying)});
  const fd = new FormData();
  fd.append('nonce', nonce);
  fd.append('response', response);
  fd.append('verify', 'true');
  fd.append('original_path', ORIGINAL_PATH);
  // FIX: 移除 fast_pass 參數，server 從 challenge cookie 取難度
  fetch(window.location.href, { method: 'POST', body: fd })
    .then(async res => {
      if (res.ok) {
        const data = await res.json();
        hideProgress();
        setMascot(IMG_OK, EMOJI_OK);
        setStatus(${JSON.stringify(STRINGS.btn_success)});
        setTimeout(() => { window.location.href = data.redirect; }, 300);
      } else {
        hideProgress();
        setMascot(IMG_FAIL, EMOJI_FAIL);
        setStatus(${JSON.stringify(STRINGS.btn_error)});
      }
    })
    .catch(() => {
      hideProgress();
      setMascot(IMG_FAIL, EMOJI_FAIL);
      setStatus(${JSON.stringify(STRINGS.btn_error)});
    });
}

// === 靜默指紋偵測 ===
async function silentFingerprintCheck() {
  let score = 0;
  const signals = [];

  if (navigator.webdriver === true) {
    score += 100; signals.push("webdriver=true");
  }

  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (ext) {
        const renderer = (gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '').toLowerCase();
        const vendor   = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '';
        const SOFT = ['swiftshader','llvmpipe','mesa offscreen','software rasterizer','brian paul','softpipe'];
        if (SOFT.some(s => renderer.includes(s))) { score += 60; signals.push("webgl_soft=" + renderer); }
        if (!vendor) { score += 20; signals.push("webgl_no_vendor"); }
      } else { score += 15; signals.push("webgl_no_debug_ext"); }
    } else { score += 30; signals.push("no_webgl"); }
  } catch (e) { score += 10; signals.push("webgl_err"); }

  try {
    const p = navigator.plugins;
    if (!p || p.length === 0) { score += 25; signals.push("no_plugins"); }
    else if (!(p instanceof PluginArray)) { score += 40; signals.push("plugins_fake"); }
  } catch (e) { score += 10; signals.push("plugins_err"); }

  try {
    if (!navigator.languages || navigator.languages.length === 0) { score += 20; signals.push("no_languages"); }
    else if (navigator.language && !navigator.languages.includes(navigator.language)) { score += 15; signals.push("lang_mismatch"); }
  } catch (e) {}

  try {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('chrome') && !ua.includes('edg') && !ua.includes('opr') && typeof window.chrome === 'undefined') {
      score += 30; signals.push("chrome_ua_no_obj");
    }
  } catch (e) {}

  try {
    const keys = ['cdc_adoQpoasnfa76pfcZLmcfl_Array','cdc_adoQpoasnfa76pfcZLmcfl_Promise','__webdriver_script_fn','__driver_evaluate'];
    if (keys.some(k => (window as any)[k] !== undefined)) { score += 80; signals.push("cdp_artifact"); }
  } catch (e) {}

  try {
    if (navigator.permissions) {
      const perm = await navigator.permissions.query({ name: 'notifications' as PermissionName });
      if (perm.state === 'granted' && score >= 20) { score += 15; signals.push("auto_notif_granted"); }
    }
  } catch (e) {}

  try {
    const c = document.createElement('canvas');
    c.width = 200; c.height = 50;
    const ctx = c.getContext('2d');
    if (ctx) {
      ctx.fillStyle = '#ff6600'; ctx.fillRect(10, 10, 50, 30);
      ctx.fillStyle = '#0066cc'; ctx.font = 'bold 14px Arial'; ctx.fillText('Albireo', 70, 30);
      const data = ctx.getImageData(0, 0, 200, 50).data;
      if (data.every(v => v === 0)) { score += 35; signals.push("canvas_blank"); }
    }
  } catch (e) {}

  try {
    if (screen.width === 0 || screen.height === 0) { score += 40; signals.push("zero_screen"); }
    else if (screen.width < 200 || screen.height < 200) { score += 20; signals.push("tiny_screen"); }
    if (window.outerWidth === 0 && window.outerHeight === 0) { score += 20; signals.push("zero_outer"); }
  } catch (e) {}

  return { score, signals };
}

// === 主流程 ===
// FIX: 移除 fast_pass 邏輯，統一走同一個流程
// 難度已由 server 根據 server-side suspicion score 決定並嵌入 HTML
// client 端指紋偵測只負責擋明顯的 bot，不再影響難度
async function run() {
  const { score, signals } = await silentFingerprintCheck();

  // 高確信度 bot → 直接封
  if (score >= 60) {
    setMascot(IMG_FAIL, EMOJI_FAIL);
    showDenied();
    return;
  }

  // 其餘走正常流程（BotD + PoW）
  // DIFFICULTY 已由 server 決定：低可疑度用 1，高可疑度用設定值
  runNormalFlow();
}

async function runNormalFlow() {
  try {
    const Botd = await import('https://openfpcdn.io/botd/v1');
    const botd = await Botd.load();
    const result = await botd.detect();
    if (result.bot) {
      setMascot(IMG_FAIL, EMOJI_FAIL);
      showDenied();
      return;
    }
  } catch (e) {
    // BotD 載入失敗 → 繼續到 PoW
  }

  mine();
}

run();
</script>
</body>
</html>
`;

// === Honeypot HTML Injector ===
class HoneypotInjector {
  private trapPath: string;
  constructor(trapPath: string) { this.trapPath = trapPath; }
  element(element: Element) {
    element.append(
      `<div aria-hidden="true" style="position:absolute;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;"><a href="${this.trapPath}" rel="nofollow" tabindex="-1">.</a></div>`,
      { html: true }
    );
  }
}

export const onRequest: PagesFunction<Env> = async (context) => {
  if (SECRET_KEY === "ALBIREO_SECRET_KEY_CHANGE_ME") {
    return new Response("SECURITY ERROR: Please change SECRET_KEY in _middleware.ts", { status: 500 });
  }

  const { request, next } = context;
  const url = new URL(request.url);
  const ua = (request.headers.get("User-Agent") || "").toLowerCase();
  const cookie = request.headers.get("Cookie") || "";

  // 1. 靜態資源直接放行
  if (
    url.pathname.match(/\.(png|jpg|jpeg|gif|webp|css|js|ico|svg|json|xml|rss|atom)$/) ||
    url.pathname.startsWith("/albireo-dist/")
  ) {
    return next();
  }

  // 2. SEO bots 白名單
  if (BOT_AGENTS.some(b => ua.includes(b))) return next();

  // 2a. Server-side suspicion scoring
  // FIX: 分數決定 PoW 難度，不再信任 client 傳的 fast_pass
  let suspicionScore = 0;
  const BOT_UA_PATTERNS = ["bot", "crawler", "spider", "scraper", "scrapy", "python-requests", "go-http-client", "curl", "wget", "libwww", "httpx"];
  if (BOT_UA_PATTERNS.some(p => ua.includes(p))) suspicionScore += 10;
  if (!request.headers.get("Accept")) suspicionScore += 5;
  if (!ua) suspicionScore += 10;
  if (!request.headers.get("Accept-Language")) suspicionScore += 5;
  if (!request.headers.get("Sec-Fetch-Mode")) suspicionScore += 5;
  if (suspicionScore >= 10) return new Response("Forbidden", { status: 403 });

  // FIX: server-side score 決定難度
  // score < 10 → 低可疑，用 difficulty=1（幾乎瞬間）
  // score >= 10 → 已被 403 擋掉（上面）
  // 0 可疑信號 → difficulty=1；有任何信號但未達 403 門檻 → 用正常 DIFFICULTY
  const serverDifficulty = suspicionScore === 0 ? 1 : DIFFICULTY;

  // 3. Honeypot 路徑偵測
  if (url.pathname.startsWith(HONEYPOT_PREFIX)) {
    const token = url.pathname.slice(HONEYPOT_PREFIX.length);
    if (await verifyHoneypotToken(token)) {
      const headers = new Headers();
      headers.append("Set-Cookie", "albireo_bot=true; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400");
      return new Response("Not Found", { status: 403, headers });
    }
    return new Response("Not Found", { status: 404 });
  }

  // 4. Bot 黑名單（honeypot 抓到的）
  if (cookie.includes("albireo_bot=true")) {
    return new Response("Forbidden", { status: 403 });
  }

  // 5. 已通過 PoW → 驗證 solved cookie HMAC 簽名後放行
  const solvedCookieStr = cookie.split(';').find(c => c.trim().startsWith('albireo_solved='));
  if (solvedCookieStr) {
    const solvedVal = decodeURIComponent(solvedCookieStr.split('=')[1].trim());
    const dotIdx = solvedVal.indexOf('.');
    if (dotIdx !== -1) {
      const ts = solvedVal.slice(0, dotIdx);
      let solvedSig = solvedVal.slice(dotIdx + 1).replace(/-/g, '+').replace(/_/g, '/');
      while (solvedSig.length % 4 !== 0) solvedSig += '=';
      const issuedAt = parseInt(ts, 10);
      const validSig = await verify("solved." + ts, solvedSig);
      const notExpired = !isNaN(issuedAt) && (Date.now() - issuedAt < 86400 * 1000);
      if (validSig && notExpired) {
        const token = await generateHoneypotToken();
        const trapPath = HONEYPOT_PREFIX + token;
        const response = await next();
        const contentType = response.headers.get("Content-Type") || "";
        if (contentType.includes("text/html")) {
          return new HTMLRewriter()
            .on("body", new HoneypotInjector(trapPath))
            .transform(response);
        }
        return response;
      }
    }
    const clearHeaders = new Headers();
    clearHeaders.append("Set-Cookie", "albireo_solved=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
    clearHeaders.set("Location", url.pathname + url.search);
    return new Response(null, { status: 302, headers: clearHeaders });
  }

  // 6. POST：PoW 驗證
  if (request.method === "POST") {
    try {
      const fd = await request.formData();
      if (!fd.has('verify')) return new Response("Bad Request", { status: 400 });
      const nonce = fd.get("nonce") as string;
      const response = fd.get("response") as string;
      const originalPath = safeRedirect(fd.get("original_path") as string || "/");

      const cStr = cookie.split(';').find(c => c.trim().startsWith('albireo_challenge='));
      if (!cStr) return new Response("Expired", { status: 403 });

      // FIX: challenge cookie 格式改為 challenge.timestamp.difficulty.sig
      // 難度從 cookie 取出，client 無法偽造
      const cookieVal = decodeURIComponent(cStr.split('=')[1].trim());
      const parts = cookieVal.split('.');
      if (parts.length !== 4) return new Response("Invalid Challenge", { status: 403 });
      const [challenge, timestamp, difficultyStr, sig] = parts;

      // FIX: 簽名涵蓋難度，防止竄改難度後重新偽造
      if (!await verify(challenge + '.' + timestamp + '.' + difficultyStr, sig)) {
        return new Response("Invalid Signature", { status: 403 });
      }

      const issuedAt = parseInt(timestamp, 10);
      if (isNaN(issuedAt) || Date.now() - issuedAt > CHALLENGE_TTL) {
        return new Response("Challenge Expired", { status: 403 });
      }

      // FIX: 難度從 cookie 取，不再看 client 傳的 fast_pass
      const powDifficulty = parseInt(difficultyStr, 10);
      if (isNaN(powDifficulty) || powDifficulty < 1) {
        return new Response("Invalid Difficulty", { status: 403 });
      }

      if (!await checkPoW(challenge, nonce, response, powDifficulty)) {
        return new Response("POW Failed", { status: 403 });
      }

      const headers = new Headers();
      const solvedTs = Date.now().toString();
      const solvedSigRaw = await sign("solved." + solvedTs);
      const solvedSigSafe = solvedSigRaw.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const solvedCookieVal = encodeURIComponent(solvedTs + "." + solvedSigSafe);
      headers.append("Set-Cookie", `albireo_solved=${solvedCookieVal}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`);
      headers.set("Content-Type", "application/json");
      return new Response(JSON.stringify({ success: true, redirect: originalPath }), { status: 200, headers });
    } catch (e) {
      return new Response("Server Error", { status: 500 });
    }
  }

  // 7. 發 Challenge
  // FIX: challenge cookie 格式加入難度，並一起簽名
  const rnd = crypto.randomUUID().replace(/-/g, '');
  const timestamp = Date.now().toString();
  const diffStr = serverDifficulty.toString();
  const payload = rnd + '.' + timestamp + '.' + diffStr;
  const sig = await sign(payload);
  const originalPath = safeRedirect(url.pathname + url.search + url.hash);
  const trapToken = await generateHoneypotToken();
  const trapPath = HONEYPOT_PREFIX + trapToken;

  const headers = new Headers();
  headers.set("Content-Type", "text/html");
  headers.set("Cache-Control", "private, no-cache, no-store, must-revalidate");
  // FIX: cookie 值包含難度
  headers.set("Set-Cookie", `albireo_challenge=${encodeURIComponent(payload + '.' + sig)}; Path=/; HttpOnly; Secure; SameSite=Lax`);

  // FIX: 把 server 決定的難度傳給 HTML，client 只能用這個難度
  const challengeHtml = GENERATE_HTML(rnd, originalPath, serverDifficulty);
  const injected = challengeHtml.replace("</body>",
    `<div aria-hidden="true" style="position:absolute;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;"><a href="${trapPath}" rel="nofollow" tabindex="-1">.</a></div></body>`
  );
  return new Response(injected, { headers });
};
