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

const STRINGS = {
  title: "Security Check | Albireo",
  heading: "Security Check",
  description: "Please verify you are human.",
  btn_calculating: "Calculating...",
  btn_verifying: "Verifying...",
  btn_success: "Success!",
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
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}
async function verify(msg: string, sig: string): Promise<boolean> {
  return (await sign(msg)) === sig;
}

// FIX: checkPoW 現在吃 bindInput（signals 摘要），跟 Node 版對齊
// bindInput 如果事後被竄改，這裡重算出來的雜湊會對不上 resp，PoW 驗證直接失敗
async function checkPoW(ch: string, nonce: string, resp: string, diff: number, bindInput?: string): Promise<boolean> {
  const msg = bindInput ? (ch + String(nonce) + '.' + bindInput) : (ch + String(nonce));
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg));
  const h = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  return h === resp && h.startsWith("0".repeat(diff));
}

// FIX2: 全部換成「原始特徵值」，不是前端算好的子分數。
// 判斷「這個特徵該扣幾分、要不要因為 Brave/Safari/Firefox RFP 而豁免」
// 這件事整套搬到伺服器端做，前端只負責蒐集事實、不做任何評分判斷。
// 跟 Node 版 signalsDigestInput 對齊：固定 key 順序，前後端序列化方式必須一致。
const SIGNAL_KEYS = [
  'webdriver', 'has_cdp_keys',
  'webgl_supported', 'webgl_has_debug_ext', 'webgl_renderer', 'webgl_vendor',
  'audio_supported', 'audio_sum_is_zero_or_nan', 'audio_threw',
  'fonts_found_count',
  'canvas_supported', 'canvas_unstable', 'canvas_data_len_low',
  'has_window_chrome', 'ua_is_chrome_like',
  'plugins_is_native_pluginarray',
  'language', 'languages', 'hardware_concurrency', 'device_memory',
  'screen_width', 'screen_height', 'outer_width', 'outer_height',
  'is_brave', 'is_safari', 'is_firefox', 'is_firefox_rfp',
  'fake_brave', 'fake_safari',
  'timing_ms'
] as const;

function signalsDigestInput(sig: Record<string, unknown>): string {
  return SIGNAL_KEYS.map(k => `${k}:${JSON.stringify(sig[k] ?? null)}`).join('|');
}

async function hashSignals(sig: Record<string, unknown>): Promise<string> {
  const input = signalsDigestInput(sig);
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('').slice(0, 16);
}

async function generateHoneypotToken(): Promise<string> {
  const ts = Date.now().toString();
  const s  = await sign("honeypot." + ts);
  return ts + "." + s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
async function verifyHoneypotToken(token: string): Promise<boolean> {
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [ts, safe] = parts;
  let s = safe.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4 !== 0) s += '=';
  const t = parseInt(ts, 10);
  if (isNaN(t) || Date.now() - t > HONEYPOT_TTL) return false;
  return verify("honeypot." + ts, s);
}
function safeRedirect(path: string): string {
  if (path.startsWith('/') && !path.startsWith('//')) return path;
  return '/';
}

// ============================================================
// Tor Exit Node 偵測（原樣保留，沒問題）
// ============================================================
const torCache = new Map<string, {result: boolean, ts: number}>();
const TOR_CACHE_TTL = 10 * 60 * 1000;

async function isTorExitNode(ip: string): Promise<boolean> {
  try {
    if (!ip || ip.includes(':')) return false;
    const parts = ip.split('.');
    if (parts.length !== 4) return false;

    const cached = torCache.get(ip);
    if (cached && Date.now() - cached.ts < TOR_CACHE_TTL) {
      return cached.result;
    }

    const reversed = parts.slice().reverse().join('.');
    const query = `${reversed}.dnsel.torproject.org`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1000);

    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${query}&type=A`,
      { headers: { 'Accept': 'application/dns-json' }, signal: controller.signal }
    );
    clearTimeout(timer);

    if (!res.ok) { torCache.set(ip, {result: false, ts: Date.now()}); return false; }

    const data: any = await res.json();
    const isTor = !!(data.Answer?.some((r: any) => r.type === 1 && r.data === '127.0.0.2'));
    torCache.set(ip, {result: isTor, ts: Date.now()});
    return isTor;
  } catch(e) {
    return false;
  }
}

// ============================================================
// FIX2: 伺服器端重新評分 —— 完整搬過來的判斷邏輯，跟前端 chk* 系列
// 的豁免規則一一對應。前端只回報「事實」(renderer 字串、screen 寬高等)，
// 要不要扣分、扣多少、豁免與否，全部由這裡重新判斷。
// 等同於 Node 版 scoreFromSignals 的嚴謹度。
// ============================================================
const SOFT_RENDERERS = ['swiftshader','llvmpipe','mesa offscreen','software rasterizer','brian paul','softpipe','angle (google)'];
const VALID_DEVICE_MEMORY = [0.25, 0.5, 1, 2, 4, 8];

function scoreFromSignals(sig: Record<string, any>) {
  let score = 0;
  const reasons: string[] = [];
  const add = (cond: boolean, pts: number, label: string) => {
    if (cond) { score += pts; reasons.push(label + '=' + pts); }
  };

  const isFF = sig.is_firefox === true;
  const isFirefoxRFP = sig.is_firefox_rfp === true;
  const isBrave = sig.is_brave === true;
  const isSafari = sig.is_safari === true;
  const audioExempt = isBrave || isSafari || isFirefoxRFP;
  const canvasExempt = isBrave || isSafari;
  const fontsExempt = isFirefoxRFP;

  // --- webdriver / CDP：跟瀏覽器種類無關，一律照實扣分 ---
  add(sig.webdriver === true, 100, 'webdriver');
  add(sig.has_cdp_keys === true, 80, 'cdp');

  // --- WebGL：對齊前端 chkWebGL 的 isFF 豁免規則 ---
  if (!isFF) {
    if (sig.webgl_supported !== true) {
      add(true, 30, 'webgl_missing');
    } else if (sig.webgl_has_debug_ext !== true) {
      add(true, 15, 'webgl_no_debug_ext');
    } else {
      const r = typeof sig.webgl_renderer === 'string' ? sig.webgl_renderer.toLowerCase() : '';
      const v = typeof sig.webgl_vendor === 'string' ? sig.webgl_vendor : '';
      if (SOFT_RENDERERS.some(s => r.includes(s))) add(true, 60, 'webgl_software');
      else if (!v) add(true, 20, 'webgl_no_vendor');
    }
  }

  // --- Audio：對齊前端 chkAudio 的豁免規則（Brave/Safari/FirefoxRFP 豁免）---
  if (!audioExempt) {
    if (sig.audio_supported !== true) add(true, isFF ? 0 : 20, 'audio_missing');
    else if (sig.audio_threw === true) add(true, isFF ? 0 : 15, 'audio_threw');
    else if (sig.audio_sum_is_zero_or_nan === true) add(true, isFF ? 0 : 50, 'audio_zero');
  }

  // --- Fonts：Firefox RFP 豁免（字型清單本來就少），非 Firefox 才扣分 ---
  if (!fontsExempt && !isFF) {
    const found = typeof sig.fonts_found_count === 'number' ? sig.fonts_found_count : 0;
    if (found <= 2) add(true, 40, 'fonts_few');
    else if (found <= 4) add(true, 15, 'fonts_some');
  }

  // --- Canvas：對齊前端 chkCanvas 的豁免規則（Brave/Safari 豁免）---
  if (!canvasExempt) {
    if (sig.canvas_supported !== true) add(true, 10, 'canvas_unsupported');
    else if (sig.canvas_unstable === true) add(true, 30, 'canvas_unstable');
    else if (sig.canvas_data_len_low === true) add(true, 35, 'canvas_short');
  }

  // --- Consistency：對齊前端 chkConsistency 逐項規則 ---
  const uaIsChromeLike = sig.ua_is_chrome_like === true;
  if (!isSafari && uaIsChromeLike && sig.has_window_chrome !== true) add(true, 30, 'fake_chrome');
  if (sig.plugins_is_native_pluginarray === false) add(true, 40, 'plugins_fake');
  if (sig.language && Array.isArray(sig.languages) && !sig.languages.includes(sig.language)) {
    add(true, 15, 'lang_mismatch');
  }
  const cores = sig.hardware_concurrency;
  if (typeof cores === 'number' && (cores < 1 || cores > 128 || !Number.isInteger(cores))) {
    add(true, 25, 'cores_anomaly');
  }
  if (!isFirefoxRFP) {
    const mem = sig.device_memory;
    if (mem !== undefined && mem !== null && !VALID_DEVICE_MEMORY.includes(mem)) {
      add(true, 20, 'memory_anomaly');
    }
    const sw = sig.screen_width, sh = sig.screen_height;
    if (sw === 0 || sh === 0) add(true, 40, 'screen_zero');
    else if (typeof sw === 'number' && typeof sh === 'number' && (sw < 200 || sh < 200)) {
      add(true, 20, 'screen_small');
    }
    if (sig.outer_width === 0 && sig.outer_height === 0) add(true, 20, 'outer_zero');
  }

  // --- Timing：跟前端 chkTiming 一致，只擋太慢 ---
  if (typeof sig.timing_ms === 'number' && sig.timing_ms > 30000) add(true, 10, 'too_slow_client');

  // --- fakeBrave / fakeSafari：前端已判斷好的矛盾訊號，直接信任布林值即可，
  // 因為這類「矛盾」本身很難靠回報假資料製造（要同時偽造多個相關聯的 API）---
  add(sig.fake_brave === true, 50, 'fake_brave');
  add(sig.fake_safari === true, 35, 'fake_safari');

  return { score, reasons };
}

// === HTML ===
const GENERATE_HTML = (challenge: string, originalPath: string, powDifficulty: number, fpNonce: string) => `
<!DOCTYPE html><html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="Cache-Control" content="no-cache,no-store,must-revalidate">
<title>${STRINGS.title}</title>
<style>
:root{--p:#00ad9f;--bg:#f4f6f8;--card:#fff;--tx:#2d3748}
@media(prefers-color-scheme:dark){:root{--bg:#121212;--card:#1e1e1e;--tx:#fff}}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.box{background:var(--card);padding:40px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.1);text-align:center;max-width:400px;width:100%}
.m{width:120px;height:120px;border-radius:50%;object-fit:cover;border:4px solid var(--card);box-shadow:0 0 0 4px var(--p);margin-bottom:20px}
.e{font-size:80px;line-height:1;margin-bottom:20px;display:none}
h1{margin-bottom:10px}
#st{margin-top:16px;font-size:.9rem;color:#888;min-height:24px}
#pb{display:none;height:4px;background:#e2e8f0;border-radius:2px;margin-top:12px;overflow:hidden}
#pf{height:100%;width:0%;background:var(--p);border-radius:2px;animation:ind 1.5s ease-in-out infinite}
@keyframes ind{0%{width:0%;margin-left:0%}50%{width:60%;margin-left:20%}100%{width:0%;margin-left:100%}}
#dm{display:none;margin-top:16px;padding:12px;background:#fff5f5;border-radius:8px;color:#c53030;font-size:.9rem}
</style>
</head>
<body>
<div class="box">
  <img src="/albireo-dist/img/pensive.webp" class="m" id="mi" alt="Guard"
    onerror="this.style.display='none';document.getElementById('me').style.display='block'">
  <div class="e" id="me">😐</div>
  <h1>${STRINGS.heading}</h1>
  <p id="dc">${STRINGS.description}</p>
  <div id="st"></div>
  <div id="pb"><div id="pf"></div></div>
  <div id="dm">${STRINGS.btn_bot_detected}<p id="dm-hint" style="margin-top:8px;font-size:.8rem;display:none"></p></div>
</div>
<script>
const CHALLENGE="${challenge}",DIFFICULTY=${powDifficulty},ORIG="${originalPath}",FP_NONCE="${fpNonce}";
const mi=document.getElementById('mi'),me=document.getElementById('me');
const st=document.getElementById('st'),pb=document.getElementById('pb');
const dm=document.getElementById('dm'),dc=document.getElementById('dc');
const ue=()=>mi.style.display==='none';
const sm=(s,e)=>{if(ue())me.innerText=e;else mi.src=s;};
const ss=m=>{st.innerText=m;};
const sp=()=>{pb.style.display='block';};
const hp=()=>{pb.style.display='none';};
const sd=(hint)=>{dm.style.display='block';dc.style.display='none';const dh=document.getElementById('dm-hint');if(hint&&dh){dh.innerText=hint;dh.style.display='block';}};

async function detectBrowser() {
  const ua=navigator.userAgent,uaLow=ua.toLowerCase();
  let isBrave=false,fakeBrave=false;
  try {
    const braveCheck = new Promise(resolve => {
      try {
        const r = navigator.brave?.isBrave?.();
        if(r && typeof r.then === 'function') {
          const timer = setTimeout(() => resolve(false), 500);
          r.then(v => { clearTimeout(timer); resolve(!!v); }).catch(() => resolve(false));
        } else {
          resolve(!!r);
        }
      } catch(e) { resolve(false); }
    });
    isBrave = !!(await braveCheck);
    if(isBrave){
      if(typeof window.chrome==='undefined'){fakeBrave=true;isBrave=false;}
      if(typeof navigator.brave?.version!=='undefined'){fakeBrave=true;isBrave=false;}
    }
  } catch(e){ isBrave=false; }
  const uaIsSafari=/^((?!chrome|android|crios|fxios).)*safari/i.test(ua);
  const hasSafariObj=typeof window.safari!=='undefined';
  let isSafari=false,fakeSafari=false;
  if(uaIsSafari){
    const isIOS=/iphone|ipad|ipod/i.test(ua);
    if(isIOS||hasSafariObj) isSafari=true;
    else fakeSafari=true;
  }
  const isFF=uaLow.includes('firefox');
  const isFirefoxRFP=isFF&&screen.width===1280&&screen.height===900;
  return{isBrave,isSafari,isFirefoxRFP,isFF,fakeBrave,fakeSafari};
}

function chkWebDriver(){return navigator.webdriver===true?100:0;}

// FIX2: chk* 系列全部改成只回報「原始事實」，不算分、不套用任何豁免邏輯。
// 誰該豁免、扣幾分，全部交給伺服器端 scoreFromSignals 判斷。
// 這樣一來，前端就算被竄改，最多只能謊報「事實」，但謊報事實一樣要付出
// 重新挖 PoW 的代價（因為事實會被雜湊進 sigDigest），而不是像舊版可以
// 直接謊報「結論」(分數) 繞過整套判斷邏輯。

function readWebGL(){
  try{
    const c=document.createElement('canvas');
    const gl=c.getContext('webgl')||c.getContext('experimental-webgl');
    if(!gl)return{webgl_supported:false,webgl_has_debug_ext:false,webgl_renderer:null,webgl_vendor:null};
    const ext=gl.getExtension('WEBGL_debug_renderer_info');
    if(!ext)return{webgl_supported:true,webgl_has_debug_ext:false,webgl_renderer:null,webgl_vendor:null};
    const r=(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)||'').toLowerCase();
    const v=(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)||'');
    return{webgl_supported:true,webgl_has_debug_ext:true,webgl_renderer:r,webgl_vendor:v||null};
  }catch(e){return{webgl_supported:false,webgl_has_debug_ext:false,webgl_renderer:null,webgl_vendor:null,webgl_threw:true};}
}

async function readAudio(){
  try{
    const AC=window.OfflineAudioContext||window.webkitOfflineAudioContext;
    if(!AC)return{audio_supported:false,audio_sum_is_zero_or_nan:false,audio_threw:false};
    const ctx=new AC(1,44100,44100);
    const osc=ctx.createOscillator(),comp=ctx.createDynamicsCompressor();
    osc.type='triangle';osc.frequency.setValueAtTime(10000,ctx.currentTime);
    comp.threshold.setValueAtTime(-50,ctx.currentTime);comp.knee.setValueAtTime(40,ctx.currentTime);
    comp.ratio.setValueAtTime(12,ctx.currentTime);comp.attack.setValueAtTime(0,ctx.currentTime);
    comp.release.setValueAtTime(0.25,ctx.currentTime);
    osc.connect(comp);comp.connect(ctx.destination);osc.start(0);
    const buf=await ctx.startRendering();
    const data=buf.getChannelData(0);
    let sum=0;for(let i=4500;i<5000;i++)sum+=Math.abs(data[i]);
    return{audio_supported:true,audio_sum_is_zero_or_nan:(sum===0||isNaN(sum)),audio_threw:false};
  }catch(e){return{audio_supported:true,audio_sum_is_zero_or_nan:false,audio_threw:true};}
}

function readFonts(){
  try{
    const c=document.createElement('canvas'),ctx=c.getContext('2d');if(!ctx)return{fonts_found_count:-1};
    const fonts=['Arial','Helvetica','Times New Roman','Courier New','Verdana',
      'Georgia','Palatino','Garamond','Bookman','Comic Sans MS',
      'Trebuchet MS','Arial Black','Impact','Calibri','Cambria',
      'Tahoma','Geneva','Optima','Futura','Century Gothic'];
    const bases=['monospace','sans-serif','serif'],str='mmmmmmmmmmlli',sz='72px ';
    const bw={};
    for(const b of bases){ctx.font=sz+b;bw[b]=ctx.measureText(str).width;}
    let found=0;
    for(const f of fonts)for(const b of bases){
      ctx.font=sz+f+','+b;
      if(ctx.measureText(str).width!==bw[b]){found++;break;}
    }
    return{fonts_found_count:found};
  }catch(e){return{fonts_found_count:-1};}
}

function readCanvas(){
  try{
    const render=()=>{
      const c=document.createElement('canvas');c.width=200;c.height=50;
      const ctx=c.getContext('2d');if(!ctx)return '';
      ctx.fillStyle='#f60';ctx.fillRect(10,10,80,30);
      ctx.fillStyle='#069';ctx.font='14px Arial';ctx.fillText('albireo2026',15,30);
      ctx.strokeStyle='#900';ctx.strokeRect(1,1,198,48);
      const g=ctx.createLinearGradient(0,0,200,0);
      g.addColorStop(0,'rgba(255,0,0,0.1)');g.addColorStop(1,'rgba(0,0,255,0.1)');
      ctx.fillStyle=g;ctx.fillRect(0,0,200,50);
      return c.toDataURL();
    };
    const r1=render(),r2=render();
    return{canvas_supported:true,canvas_unstable:(r1!==r2),canvas_data_len_low:(!r1||r1.length<100)};
  }catch(e){return{canvas_supported:false,canvas_unstable:false,canvas_data_len_low:false};}
}

function readCDP(){
  try{
    const keys=['cdc_adoQpoasnfa76pfcZLmcfl_Array','cdc_adoQpoasnfa76pfcZLmcfl_Promise',
      '__webdriver_script_fn','__driver_evaluate','__webdriver_evaluate',
      '__selenium_evaluate','__fxdriver_evaluate','__driver_unwrapped','__webdriver_unwrapped'];
    return keys.some(k=>window[k]!==undefined);
  }catch(e){return false;}
}

function readConsistency(){
  try{
    const ua=navigator.userAgent.toLowerCase();
    const uaIsChromeLike=ua.includes('chrome')&&!ua.includes('edg')&&!ua.includes('opr')&&!ua.includes('samsung');
    return{
      has_window_chrome: typeof window.chrome!=='undefined',
      ua_is_chrome_like: uaIsChromeLike,
      plugins_is_native_pluginarray: navigator.plugins ? (navigator.plugins instanceof PluginArray) : true,
      language: navigator.language||null,
      languages: navigator.languages ? Array.from(navigator.languages) : [],
      hardware_concurrency: navigator.hardwareConcurrency||0,
      device_memory: navigator.deviceMemory!==undefined ? navigator.deviceMemory : null,
      screen_width: screen.width,
      screen_height: screen.height,
      outer_width: window.outerWidth,
      outer_height: window.outerHeight
    };
  }catch(e){
    return{has_window_chrome:false,ua_is_chrome_like:false,plugins_is_native_pluginarray:true,
      language:null,languages:[],hardware_concurrency:0,device_memory:null,
      screen_width:0,screen_height:0,outer_width:0,outer_height:0};
  }
}

// FIX2: SIGNAL_KEYS 跟伺服器端完全對齊（原始事實，不是分數）
const SIGNAL_KEYS=[
  'webdriver','has_cdp_keys',
  'webgl_supported','webgl_has_debug_ext','webgl_renderer','webgl_vendor',
  'audio_supported','audio_sum_is_zero_or_nan','audio_threw',
  'fonts_found_count',
  'canvas_supported','canvas_unstable','canvas_data_len_low',
  'has_window_chrome','ua_is_chrome_like',
  'plugins_is_native_pluginarray',
  'language','languages','hardware_concurrency','device_memory',
  'screen_width','screen_height','outer_width','outer_height',
  'is_brave','is_safari','is_firefox','is_firefox_rfp',
  'fake_brave','fake_safari',
  'timing_ms'
];
function clientSignalsDigestInput(sig){
  return SIGNAL_KEYS.map(k=>k+':'+JSON.stringify(sig[k]===undefined?null:sig[k])).join('|');
}
async function hashSignalsClient(sig){
  const input=clientSignalsDigestInput(sig);
  const buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('').slice(0,16);
}

// 本地「預估」分數，純粹拿來決定要不要先秀拒絕畫面、要不要多跑一次 BotD。
// 這份計分邏輯刻意跟伺服器端保持同步，但即使跟伺服器算出來的不完全一致也沒關係 ——
// 因為最終准不准，一律是伺服器拿同一包原始 signals 重算之後才決定，
// 這裡算錯或被竄改，最多只是前端畫面誤判，不影響後端真正的判斷。
function localEstimateScore(sig){
  let s=0;
  if(sig.webdriver)s+=100;
  if(sig.has_cdp_keys)s+=80;
  const isFF=sig.is_firefox;
  if(!isFF){
    if(!sig.webgl_supported)s+=30;
    else if(!sig.webgl_has_debug_ext)s+=15;
    else{
      const SOFT=['swiftshader','llvmpipe','mesa offscreen','software rasterizer','brian paul','softpipe','angle (google)'];
      const r=sig.webgl_renderer||'';
      if(SOFT.some(x=>r.includes(x)))s+=60;else if(!sig.webgl_vendor)s+=20;
    }
  }
  const audioExempt=sig.is_brave||sig.is_safari||sig.is_firefox_rfp;
  if(!audioExempt){
    if(!sig.audio_supported)s+=isFF?0:20;
    else if(sig.audio_threw)s+=isFF?0:15;
    else if(sig.audio_sum_is_zero_or_nan)s+=isFF?0:50;
  }
  if(!sig.is_firefox_rfp&&!isFF){
    if(sig.fonts_found_count<=2)s+=40;else if(sig.fonts_found_count<=4)s+=15;
  }
  const canvasExempt=sig.is_brave||sig.is_safari;
  if(!canvasExempt){
    if(!sig.canvas_supported)s+=10;else if(sig.canvas_unstable)s+=30;else if(sig.canvas_data_len_low)s+=35;
  }
  if(!sig.is_safari&&sig.ua_is_chrome_like&&!sig.has_window_chrome)s+=30;
  if(sig.plugins_is_native_pluginarray===false)s+=40;
  if(sig.language&&sig.languages&&!sig.languages.includes(sig.language))s+=15;
  const cores=sig.hardware_concurrency;
  if(cores&&(cores<1||cores>128||!Number.isInteger(cores)))s+=25;
  if(!sig.is_firefox_rfp){
    const mem=sig.device_memory;
    if(mem!==undefined&&mem!==null&&![0.25,0.5,1,2,4,8].includes(mem))s+=20;
    if(sig.screen_width===0||sig.screen_height===0)s+=40;
    else if(sig.screen_width<200||sig.screen_height<200)s+=20;
    if(sig.outer_width===0&&sig.outer_height===0)s+=20;
  }
  if(sig.fake_brave)s+=50;
  if(sig.fake_safari)s+=35;
  return s;
}

let lastSignals={},sigDigest='',t0Start=0;
async function run(){
  const t0=Date.now();t0Start=t0;
  const{isBrave,isSafari,isFirefoxRFP,isFF,fakeBrave,fakeSafari}=await detectBrowser();
  const[audio,fonts]=await Promise.all([readAudio(),Promise.resolve(readFonts())]);
  const webgl=readWebGL();
  const canvas=readCanvas();
  const consistency=readConsistency();
  const hasCdp=readCDP();
  const webdriverFlag=navigator.webdriver===true;
  const timingMs=Date.now()-t0;

  // FIX2: 送「原始事實」給伺服器，不送任何算好的分數或結論
  lastSignals={
    webdriver: webdriverFlag,
    has_cdp_keys: hasCdp,
    webgl_supported: webgl.webgl_supported,
    webgl_has_debug_ext: webgl.webgl_has_debug_ext,
    webgl_renderer: webgl.webgl_renderer,
    webgl_vendor: webgl.webgl_vendor,
    audio_supported: audio.audio_supported,
    audio_sum_is_zero_or_nan: audio.audio_sum_is_zero_or_nan,
    audio_threw: audio.audio_threw,
    fonts_found_count: fonts.fonts_found_count,
    canvas_supported: canvas.canvas_supported,
    canvas_unstable: canvas.canvas_unstable,
    canvas_data_len_low: canvas.canvas_data_len_low,
    has_window_chrome: consistency.has_window_chrome,
    ua_is_chrome_like: consistency.ua_is_chrome_like,
    plugins_is_native_pluginarray: consistency.plugins_is_native_pluginarray,
    language: consistency.language,
    languages: consistency.languages,
    hardware_concurrency: consistency.hardware_concurrency,
    device_memory: consistency.device_memory,
    screen_width: consistency.screen_width,
    screen_height: consistency.screen_height,
    outer_width: consistency.outer_width,
    outer_height: consistency.outer_height,
    is_brave: isBrave,
    is_safari: isSafari,
    is_firefox: isFF,
    is_firefox_rfp: isFirefoxRFP,
    fake_brave: fakeBrave,
    fake_safari: fakeSafari,
    timing_ms: timingMs
  };
  sigDigest = await hashSignalsClient(lastSignals);

  // 本地預估分數只決定「要不要先在畫面上秀拒絕、要不要多跑一次 BotD 二次確認」，
  // 不是最終防線 —— 真正准不准，由伺服器對同一包 lastSignals 重新計分決定
  const localScore = localEstimateScore(lastSignals);

  if(localScore>=60){sm('/albireo-dist/img/reject.webp','❌');sd('If verification fails, please try disabling Brave Shields or privacy extensions for this site, then refresh. / 若驗證失敗，請嘗試關閉 Brave Shields 或隱私擴充功能後重新整理。');return;}
  if(localScore>=10){
    try{
      const Botd=await import('https://openfpcdn.io/botd/v1');
      const botd=await Botd.load();
      const result=await botd.detect();
      if(result.bot){sm('/albireo-dist/img/reject.webp','❌');sd('If verification fails, please try disabling Brave Shields or privacy extensions for this site, then refresh. / 若驗證失敗，請嘗試關閉 Brave Shields 或隱私擴充功能後重新整理。');return;}
    }catch(e){}
  }
  mine();
}

// FIX: worker 現在吃 sigDigest,混進 PoW 雜湊輸入
const WC=\`
async function h(s){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));return Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');}
self.onmessage=async e=>{const{challenge,difficulty,startNonce,step,sigDigest}=e.data;const p="0".repeat(difficulty);let n=startNonce;const suffix=sigDigest?("."+sigDigest):"";while(true){const hash=await h(challenge+n+suffix);if(hash.startsWith(p)){self.postMessage({nonce:n,hash});return;}n+=step;}};
\`;

function mine(){
  ss(${JSON.stringify(STRINGS.btn_calculating)});sp();
  const n=Math.max(1,(navigator.hardwareConcurrency||4)-1);
  const ws=[];let done=false;
  for(let i=0;i<n;i++){
    const w=new Worker(URL.createObjectURL(new Blob([WC],{type:'application/javascript'})));
    ws.push(w);w.postMessage({challenge:CHALLENGE,difficulty:DIFFICULTY,startNonce:i,step:n,sigDigest:sigDigest});
    w.onmessage=e=>{if(done)return;done=true;ws.forEach(x=>x.terminate());submit(e.data.nonce,e.data.hash);};
  }
}

function submit(nonce,response){
  ss(${JSON.stringify(STRINGS.btn_verifying)});
  const fd=new FormData();
  fd.append('nonce',String(nonce));fd.append('response',response);
  fd.append('verify','true');fd.append('original_path',ORIG);
  // FIX: 送原始 signals JSON，不送裸分數
  fd.append('signals',JSON.stringify(lastSignals));fd.append('fp_nonce',FP_NONCE);
  fd.append('elapsed',String(Date.now()-t0Start));
  fetch(window.location.href,{method:'POST',body:fd})
    .then(async r=>{
      if(r.ok){const d=await r.json();hp();sm('/albireo-dist/img/happy.webp','😊');ss(${JSON.stringify(STRINGS.btn_success)});setTimeout(()=>{window.location.href=d.redirect;},300);}
      else{
        hp();sm('/albireo-dist/img/reject.webp','❌');
        sd('If verification fails, please try disabling Brave Shields or privacy extensions for this site, then refresh. / 若驗證失敗，請嘗試關閉 Brave Shields 或隱私擴充功能後重新整理。');
      }
    })
    .catch(()=>{hp();sm('/albireo-dist/img/reject.webp','❌');sd('If verification fails, please try disabling Brave Shields or privacy extensions for this site, then refresh. / 若驗證失敗，請嘗試關閉 Brave Shields 或隱私擴充功能後重新整理。');});
}

run().catch(e=>{ hp(); sm('/albireo-dist/img/reject.webp','❌'); sd('If verification fails, please try disabling Brave Shields or privacy extensions for this site, then refresh. / 若驗證失敗，請嘗試關閉 Brave Shields 或隱私擴充功能後重新整理。'); });
</script>
</body></html>
`;

class HoneypotInjector {
  private t: string;
  constructor(t: string){this.t=t;}
  element(el: Element){
    el.append(
      `<div aria-hidden="true" style="position:absolute;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;"><a href="${this.t}" rel="nofollow" tabindex="-1">.</a></div>`,
      {html:true}
    );
  }
}

export const onRequest: PagesFunction<Env> = async (context) => {
  if(SECRET_KEY==="ALBIREO_SECRET_KEY_CHANGE_ME"){
    return new Response("SECURITY ERROR: Please change SECRET_KEY",{status:500});
  }

  const{request,next}=context;
  const url=new URL(request.url);
  const ua=(request.headers.get("User-Agent")||"").toLowerCase();
  const cookie=request.headers.get("Cookie")||"";

  if(url.pathname.match(/\.(png|jpg|jpeg|gif|webp|css|js|ico|svg|json|xml|rss|atom)$/)||
     url.pathname.startsWith("/albireo-dist/")) return next();

  if(BOT_AGENTS.some(b=>ua.includes(b))) return next();

  const clientIP = request.headers.get("CF-Connecting-IP") || "";
  if(clientIP && await isTorExitNode(clientIP)){
    return new Response("Forbidden", { status: 403 });
  }

  let sus=0;
  const BOTS=["bot","crawler","spider","scraper","scrapy","python-requests","go-http-client","curl","wget","libwww","httpx"];
  if(BOTS.some(p=>ua.includes(p)))            sus+=10;
  if(!request.headers.get("Accept"))          sus+=5;
  if(!ua)                                     sus+=10;
  if(!request.headers.get("Accept-Language")) sus+=5;
  if(!request.headers.get("Sec-Fetch-Mode"))  sus+=5;
  if(sus>=10) return new Response("Forbidden",{status:403});

  const serverDiff=sus===0?1:DIFFICULTY;

  if(url.pathname.startsWith(HONEYPOT_PREFIX)){
    const token=url.pathname.slice(HONEYPOT_PREFIX.length);
    if(await verifyHoneypotToken(token)){
      const h=new Headers();
      h.append("Set-Cookie","albireo_bot=true; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400");
      return new Response("Not Found",{status:403,headers:h});
    }
    return new Response("Not Found",{status:404});
  }

  if(cookie.includes("albireo_bot=true")) return new Response("Forbidden",{status:403});

  const solvedStr=cookie.split(';').find(c=>c.trim().startsWith('albireo_solved='));
  if(solvedStr){
    const val=decodeURIComponent(solvedStr.split('=')[1].trim());
    const dot=val.indexOf('.');
    if(dot!==-1){
      const ts=val.slice(0,dot);
      let sig=val.slice(dot+1).replace(/-/g,'+').replace(/_/g,'/');
      while(sig.length%4!==0)sig+='=';
      const t=parseInt(ts,10);
      if(!isNaN(t)&&Date.now()-t<86400000&&await verify("solved."+ts,sig)){
        const token=await generateHoneypotToken();
        const res=await next();
        const ct=res.headers.get("Content-Type")||"";
        if(ct.includes("text/html")){
          return new HTMLRewriter().on("body",new HoneypotInjector(HONEYPOT_PREFIX+token)).transform(res);
        }
        return res;
      }
    }
    const h=new Headers();
    h.append("Set-Cookie","albireo_solved=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
    h.set("Location",url.pathname+url.search);
    return new Response(null,{status:302,headers:h});
  }

  // POST: PoW + 訊號驗證
  if(request.method==="POST"){
    try{
      const fd=await request.formData();
      if(!fd.has('verify'))return new Response("Bad Request",{status:400});
      const nonce=fd.get("nonce") as string;
      const resp=fd.get("response") as string;
      const orig=safeRedirect(fd.get("original_path") as string||"/");
      const cStr=cookie.split(';').find(c=>c.trim().startsWith('albireo_challenge='));
      if(!cStr)return new Response("Expired",{status:403});
      const cv=decodeURIComponent(cStr.split('=')[1].trim());
      const parts=cv.split('.');
      if(parts.length!==5)return new Response("Invalid Challenge",{status:403});
      const[ch,ts,diffStr,cookieFpNonce,sig]=parts;
      if(!await verify(ch+'.'+ts+'.'+diffStr+'.'+cookieFpNonce,sig))return new Response("Invalid Signature",{status:403});
      const issued=parseInt(ts,10);
      if(isNaN(issued)||Date.now()-issued>CHALLENGE_TTL)return new Response("Challenge Expired",{status:403});
      const diff=parseInt(diffStr,10);
      if(isNaN(diff)||diff<1)return new Response("Invalid Difficulty",{status:403});

      // FIX: 解析客戶端回報的「原始訊號」，不是分數
      let parsedSignals: Record<string, any> = {};
      try { parsedSignals = JSON.parse((fd.get("signals") as string) || "{}"); }
      catch (e) { return new Response("Invalid Signals", {status:400}); }

      // FIX: 把 signals 雜湊後當成 PoW 的綁定輸入
      // 客戶端挖礦時用的 sigDigest 必須跟這裡重算出來的一致，
      // 事後竄改 signals 會讓這裡算出不同摘要，PoW 核驗失敗
      const sigDigest = await hashSignals(parsedSignals);
      const ok = await checkPoW(ch, nonce, resp, diff, sigDigest);
      if (!ok) return new Response("POW Failed", {status:403});

      const clientFpNonce=fd.get("fp_nonce") as string||"";
      if(clientFpNonce!==cookieFpNonce)return new Response("Fingerprint Token Mismatch",{status:403});

      // FIX: 伺服器自己重新計分，不信任任何前端送來的總分欄位
      const { score, reasons } = scoreFromSignals(parsedSignals);
      if (score >= 60) return new Response("Bot Detected", {status:403});

      const elapsed=parseInt(fd.get("elapsed") as string||"0",10);
      if(isNaN(elapsed)||elapsed<10)return new Response("Too Fast",{status:403});
      if(elapsed>CHALLENGE_TTL)return new Response("Too Slow",{status:403});

      const sts=Date.now().toString();
      const rs=await sign("solved."+sts);
      const ss2=rs.replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
      const cv2=encodeURIComponent(sts+"."+ss2);
      const h=new Headers();
      h.append("Set-Cookie",`albireo_solved=${cv2}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`);
      h.set("Content-Type","application/json");
      return new Response(JSON.stringify({success:true,redirect:orig}),{status:200,headers:h});
    }catch(e){return new Response("Server Error",{status:500});}
  }

  // 發 Challenge
  const rnd=crypto.randomUUID().replace(/-/g,'');
  const ts=Date.now().toString();
  const ds=serverDiff.toString();
  const fpNonce=crypto.randomUUID().replace(/-/g,'');
  const payload=rnd+'.'+ts+'.'+ds+'.'+fpNonce;
  const sig=await sign(payload);
  const orig=safeRedirect(url.pathname+url.search+url.hash);
  const trap=await generateHoneypotToken();
  const h=new Headers();
  h.set("Content-Type","text/html");
  h.set("Cache-Control","private,no-cache,no-store,must-revalidate");
  h.set("Set-Cookie",`albireo_challenge=${encodeURIComponent(payload+'.'+sig)}; Path=/; HttpOnly; Secure; SameSite=Lax`);
  const html=GENERATE_HTML(rnd,orig,serverDiff,fpNonce);
  const injected=html.replace("</body>",
    `<div aria-hidden="true" style="position:absolute;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;"><a href="${HONEYPOT_PREFIX+trap}" rel="nofollow" tabindex="-1">.</a></div></body>`
  );
  return new Response(injected,{headers:h});
};
