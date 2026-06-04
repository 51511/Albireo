import { NextRequest, NextResponse } from 'next/server';

// === Configuration ===
const DIFFICULTY = 5; // 可調整難度：數字越大越慢，建議 3~6
const SECRET_KEY = "VERCEL_ALBIREO_SECRET_KEY_CHANGE_ME"; // ★ 請務必修改這裡
const BOT_AGENTS = ["google", "bingbot", "yahoo", "duckduckbot"];
const CHALLENGE_TTL = 5 * 60 * 1000; // Challenge 過期時間（毫秒），預設 5 分鐘

// === UI Strings（可自訂語言）===
const STRINGS = {
    title: "Security Check | Albireo",
    heading: "Security Check",
    description: "Please verify you are human.",
    btn_start: "I am human",
    btn_calculating: "Calculating...",
    btn_verifying: "Verifying...",
    btn_success: "Success!",
    btn_retry: "Retry",
    btn_error: "Error",
};

// === Crypto Utils ===
async function sign(msg: string): Promise<string> {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(SECRET_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function verify(msg: string, sig: string): Promise<boolean> {
    const expected = await sign(msg);
    return expected === sig;
}

async function checkPoW(challenge: string, nonce: string, response: string, difficulty: number): Promise<boolean> {
    const msg = challenge + String(nonce);
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(msg));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const calculated = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    if (calculated !== response) return false;
    const prefix = "0".repeat(difficulty);
    if (!calculated.startsWith(prefix)) return false;
    return true;
}

// === Safe Redirect Validator ===
function safeRedirect(path: string): string {
    try {
        if (path.startsWith('/') && !path.startsWith('//')) return path;
    } catch (_) {}
    return '/';
}

// === HTML Generator ===
const GENERATE_HTML = (challenge: string, originalPath: string) => `
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
button { background: var(--primary); color: white; border: none; padding: 12px 30px; border-radius: 8px; font-size: 1rem; cursor: pointer; margin-top: 20px; width: 100%; }
button:disabled { opacity: 0.7; }
</style>
</head>
<body>
<div class="box">
<img src="/albireo-dist/img/pensive.webp" class="mascot" id="mascot-img" alt="Guard"
onerror="this.style.display='none'; document.getElementById('mascot-emoji').style.display='block';">
<div class="mascot-emoji" id="mascot-emoji">😐</div>
<h1>${STRINGS.heading}</h1>
<p>${STRINGS.description}</p>
<button id="verify-btn">${STRINGS.btn_start}</button>
</div>
<script>
const CHALLENGE = "${challenge}";
const DIFFICULTY = ${DIFFICULTY};
const ORIGINAL_PATH = "${originalPath}";
const IMG_CHECK = "/albireo-dist/img/pensive.webp";
const IMG_SUCCESS = "/albireo-dist/img/happy.webp";
const IMG_FAILED = "/albireo-dist/img/reject.webp";
const EMOJI_CHECK = "😐";
const EMOJI_SUCCESS = "😊";
const EMOJI_FAILED = "❌";
const S = {
    calculating: ${JSON.stringify(STRINGS.btn_calculating)},
    verifying: ${JSON.stringify(STRINGS.btn_verifying)},
    success: ${JSON.stringify(STRINGS.btn_success)},
    retry: ${JSON.stringify(STRINGS.btn_retry)},
    error: ${JSON.stringify(STRINGS.btn_error)},
};
const btn = document.getElementById('verify-btn');
const img = document.getElementById('mascot-img');
const emoji = document.getElementById('mascot-emoji');
const usingEmoji = () => img.style.display === 'none';

function setMascot(imgSrc, emojiChar) {
    if (usingEmoji()) {
        emoji.innerText = emojiChar;
    } else {
        img.src = imgSrc;
    }
}

const WORKER_CODE = \`
async function sha256(str) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
self.onmessage = async (e) => {
    const { challenge, difficulty, startNonce, step } = e.data;
    const prefix = "0".repeat(difficulty);
    let nonce = startNonce;
    while (true) {
        const hash = await sha256(challenge + nonce);
        if (hash.startsWith(prefix)) {
            self.postMessage({ found: true, nonce, hash });
            return;
        }
        nonce += step;
    }
};
\`;

function createWorker() {
    const blob = new Blob([WORKER_CODE], { type: 'application/javascript' });
    return new Worker(URL.createObjectURL(blob));
}

function mine() {
    btn.disabled = true; btn.innerText = S.calculating;
    setMascot(IMG_CHECK, EMOJI_CHECK);

    const numWorkers = Math.max(1, (navigator.hardwareConcurrency || 4) - 1);
    const workers = [];
    let done = false;

    for (let i = 0; i < numWorkers; i++) {
        const worker = createWorker();
        workers.push(worker);
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
    btn.innerText = S.verifying;
    const fd = new FormData();
    fd.append('nonce', nonce);
    fd.append('response', response);
    fd.append('verify', 'true');
    fd.append('original_path', ORIGINAL_PATH);

    fetch(window.location.href, { method: 'POST', body: fd }).then(async res => {
        if (res.ok) {
            const data = await res.json();
            setMascot(IMG_SUCCESS, EMOJI_SUCCESS);
            btn.innerText = S.success;
            setTimeout(() => { window.location.href = data.redirect; }, 500);
        } else {
            setMascot(IMG_FAILED, EMOJI_FAILED);
            btn.innerText = S.retry; btn.disabled = false;
        }
    }).catch(() => {
        setMascot(IMG_FAILED, EMOJI_FAILED);
        btn.innerText = S.error; btn.disabled = false;
    });
}

btn.addEventListener('click', mine);
</script>
</body>
</html>
`;

// === Vercel Middleware Entry Point ===
export async function middleware(request: NextRequest) {
    if (SECRET_KEY === "VERCEL_ALBIREO_SECRET_KEY_CHANGE_ME") {
        return new NextResponse("SECURITY ERROR: Please change SECRET_KEY in middleware.ts", { status: 500 });
    }

    const url = request.nextUrl;
    const ua = (request.headers.get("User-Agent") || "").toLowerCase();

    // 1. SEO bots 白名單 → 直接放行，跳過評分系統
    if (BOT_AGENTS.some(b => ua.includes(b))) return NextResponse.next();

    // 1a. ★ 評分系統（白名單已放行，這裡只處理非白名單的請求）
    let suspicionScore = 0;

    // UA 含已知爬蟲特徵 → +10
    const BOT_UA_PATTERNS = ["bot", "crawler", "spider", "scraper", "python-requests", "go-http-client", "curl", "wget", "libwww", "httpx"];
    if (BOT_UA_PATTERNS.some(p => ua.includes(p))) suspicionScore += 10;

    // 沒有 Accept header → +5（真實瀏覽器一定會帶）
    const accept = request.headers.get("Accept") || "";
    if (!accept) suspicionScore += 5;

    // 沒有 User-Agent → +10（幾乎不可能是真人）
    if (!ua) suspicionScore += 10;

    // score >= 10 → DENY
    if (suspicionScore >= 10) {
        return new NextResponse("Forbidden", { status: 403 });
    }

    // 2. Check Cookie
    const cookie = request.headers.get("Cookie") || "";
    if (cookie.includes("albireo_solved=true")) return NextResponse.next();

    // 3. Handle POST
    if (request.method === "POST") {
        try {
            const fd = await request.formData();
            if (!fd.has('verify')) return new NextResponse("Bad Request", { status: 400 });

            const nonce = fd.get("nonce") as string;
            const response = fd.get("response") as string;
            const originalPath = safeRedirect(fd.get("original_path") as string || "/");

            const cStr = cookie.split(';').find(c => c.trim().startsWith('albireo_challenge='));
            if (!cStr) return new NextResponse("Expired", { status: 403 });

            const [challenge, timestamp, sig] = decodeURIComponent(cStr.split('=')[1].trim()).split('.');

            if (!await verify(challenge + '.' + timestamp, sig)) return new NextResponse("Invalid Signature", { status: 403 });

            const issuedAt = parseInt(timestamp, 10);
            if (isNaN(issuedAt) || Date.now() - issuedAt > CHALLENGE_TTL) {
                return new NextResponse("Challenge Expired", { status: 403 });
            }

            if (!await checkPoW(challenge, nonce, response, DIFFICULTY)) return new NextResponse("POW Failed", { status: 403 });

            const res = new NextResponse(JSON.stringify({ success: true, redirect: originalPath }), { status: 200 });
            res.headers.set("Content-Type", "application/json");
            res.cookies.set("albireo_solved", "true", {
                path: "/",
                httpOnly: true,
                secure: true,
                sameSite: "lax",
                maxAge: 86400,
            });

            return res;
        } catch (e) {
            return new NextResponse("Server Error", { status: 500 });
        }
    }

    // 4. Issue Challenge
    const rnd = crypto.randomUUID().replace(/-/g, '');
    const timestamp = Date.now().toString();
    const payload = rnd + '.' + timestamp;
    const sig = await sign(payload);
    const originalPath = safeRedirect(url.pathname + url.search + url.hash);

    const res = new NextResponse(GENERATE_HTML(rnd, originalPath), { status: 200 });
    res.headers.set("Content-Type", "text/html");
    res.headers.set("Cache-Control", "private, no-cache, no-store, must-revalidate");
    res.cookies.set("albireo_challenge", encodeURIComponent(payload + '.' + sig), {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "lax",
    });

    return res;
}

export const config = {
    matcher: [
        // 攔截所有路徑，排除靜態資源
        '/((?!_next/static|_next/image|favicon.ico|albireo-dist|.*\\.(?:png|jpg|jpeg|gif|webp|css|js|ico|svg|json|xml|rss|atom)$).*)',
    ],
};
