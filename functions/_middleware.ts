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
async function checkPoW(ch: string, nonce: string, resp: string, diff: number): Promise<boolean> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ch + String(nonce)));
  const h = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  return h === resp && h.startsWith("0".repeat(diff));
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
// Tor Exit Node 偵測
// 使用 Tor Project 官方 DNSEL + in-memory cache
// ============================================================

// 簡單 in-memory cache，避免同一 IP 重複查詢
// Cloudflare Workers 每個 isolate 共用，有效降低 DoH 查詢頻率
const torCache = new Map<string, {result: boolean, ts: number}>();
const TOR_CACHE_TTL = 10 * 60 * 1000; // 10 分鐘

async function isTorExitNode(ip: string): Promise<boolean> {
  try {
    if (!ip || ip.includes(':')) return false;
    const parts = ip.split('.');
    if (parts.length !== 4) return false;

    // 查快取
    const cached = torCache.get(ip);
    if (cached && Date.now() - cached.ts < TOR_CACHE_TTL) {
      return cached.result;
    }

    const reversed = parts.slice().reverse().join('.');
    const query = `${reversed}.dnsel.torproject.org`;

    // timeout 1秒，失敗放行
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
    return false; // 查詢失敗 → 放行，不誤傷
  }
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
    // isBrave() 有時會拋出例外，加 timeout 防止卡住
    const braveCheck = new Promise(resolve => {
      try {
        const r = navigator.brave?.isBrave?.();
        if(r && typeof r.then === 'function') {
          // 設 500ms timeout，超時視為非 Brave
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
  // Tor 已在 server-side 擋掉，client-side 不再需要偵測
  return{isBrave,isSafari,isFirefoxRFP,fakeBrave,fakeSafari};
}

function chkWebDriver(){return navigator.webdriver===true?100:0;}

function chkWebGL(){
  try{
    const c=document.createElement('canvas');
    const gl=c.getContext('webgl')||c.getContext('experimental-webgl');
    if(!gl)return 30;
    const ext=gl.getExtension('WEBGL_debug_renderer_info');
    if(!ext)return 15;
    const r=(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)||'').toLowerCase();
    const v=(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)||'').toLowerCase();
    const SOFT=['swiftshader','llvmpipe','mesa offscreen','software rasterizer','brian paul','softpipe','angle (google)'];
    if(SOFT.some(s=>r.includes(s)))return 60;
    if(!v)return 20;
    return 0;
  }catch(e){return 10;}
}

async function chkAudio(exempt){
  if(exempt)return 0;
  try{
    const AC=window.OfflineAudioContext||window.webkitOfflineAudioContext;
    if(!AC)return 20;
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
    if(sum===0||isNaN(sum))return 50;
    return 0;
  }catch(e){return 15;}
}

function chkFonts(exempt){
  if(exempt)return 0;
  try{
    const c=document.createElement('canvas'),ctx=c.getContext('2d');if(!ctx)return 10;
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
    if(found<=2)return 40;if(found<=4)return 15;return 0;
  }catch(e){return 10;}
}

function chkCanvas(exempt){
  if(exempt)return 0;
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
    if(r1!==r2)return 30;if(!r1||r1.length<100)return 35;return 0;
  }catch(e){return 10;}
}

function chkCDP(){
  try{
    const keys=['cdc_adoQpoasnfa76pfcZLmcfl_Array','cdc_adoQpoasnfa76pfcZLmcfl_Promise',
      '__webdriver_script_fn','__driver_evaluate','__webdriver_evaluate',
      '__selenium_evaluate','__fxdriver_evaluate','__driver_unwrapped','__webdriver_unwrapped'];
    if(keys.some(k=>window[k]!==undefined))return 80;
    return 0;
  }catch(e){return 0;}
}

function chkConsistency(isSafari,isFirefoxRFP){
  let s=0;
  try{
    const ua=navigator.userAgent.toLowerCase();
    const isChrome=ua.includes('chrome')&&!ua.includes('edg')&&!ua.includes('opr')&&!ua.includes('samsung');
    if(!isSafari&&isChrome&&typeof window.chrome==='undefined')s+=30;
    if(navigator.plugins&&!(navigator.plugins instanceof PluginArray))s+=40;
    if(navigator.language&&navigator.languages&&!navigator.languages.includes(navigator.language))s+=15;
    const cores=navigator.hardwareConcurrency;
    if(cores&&(cores<1||cores>128||!Number.isInteger(cores)))s+=25;
    if(!isFirefoxRFP){
      const mem=navigator.deviceMemory;
      if(mem!==undefined&&![0.25,0.5,1,2,4,8].includes(mem))s+=20;
      if(screen.width===0||screen.height===0)s+=40;
      else if(screen.width<200||screen.height<200)s+=20;
      if(window.outerWidth===0&&window.outerHeight===0)s+=20;
    }
  }catch(e){}
  return s;
}

function chkTiming(t0){
  const ms=Date.now()-t0;
  if(ms<50)return 20;if(ms>30000)return 10;return 0;
}

let lastScore=0,t0Start=0;
async function run(){
  const t0=Date.now();t0Start=t0;
  const{isBrave,isSafari,isFirefoxRFP,fakeBrave,fakeSafari}=await detectBrowser();
  const[audioScore,fontScore]=await Promise.all([
    chkAudio(isBrave||isSafari||isFirefoxRFP),
    Promise.resolve(chkFonts(isFirefoxRFP)),
  ]);
  let score=0;const sigs=[];
  const add=(s,l)=>{if(s>0){score+=s;sigs.push(l+'='+s);}};
  add(chkWebDriver(),'webdriver');
  add(chkWebGL(),'webgl');
  add(audioScore,'audio');
  add(fontScore,'fonts');
  add(chkCanvas(isBrave||isSafari),'canvas');
  add(chkCDP(),'cdp');
  add(chkConsistency(isSafari,isFirefoxRFP),'consistency');
  add(chkTiming(t0),'timing');
  if(fakeBrave){score+=50;sigs.push('fake_brave=50');}
  lastScore=score; // 存給 submit() 用
  if(fakeSafari){score+=35;sigs.push('fake_safari=35');}
  if(score>=60){sm('/albireo-dist/img/reject.webp','❌');sd('If verification fails, please try disabling Brave Shields or privacy extensions for this site, then refresh. / 若驗證失敗，請嘗試關閉 Brave Shields 或隱私擴充功能後重新整理。');return;}
  if(score>=10){
    try{
      const Botd=await import('https://openfpcdn.io/botd/v1');
      const botd=await Botd.load();
      const result=await botd.detect();
      if(result.bot){sm('/albireo-dist/img/reject.webp','❌');sd('If verification fails, please try disabling Brave Shields or privacy extensions for this site, then refresh. / 若驗證失敗，請嘗試關閉 Brave Shields 或隱私擴充功能後重新整理。');return;}
    }catch(e){}
  }
  mine();
}

const WC=\`
async function h(s){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));return Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');}
self.onmessage=async e=>{const{challenge,difficulty,startNonce,step}=e.data;const p="0".repeat(difficulty);let n=startNonce;while(true){const hash=await h(challenge+n);if(hash.startsWith(p)){self.postMessage({nonce:n,hash});return;}n+=step;}};
\`;

function mine(){
  ss(${JSON.stringify(STRINGS.btn_calculating)});sp();
  const n=Math.max(1,(navigator.hardwareConcurrency||4)-1);
  const ws=[];let done=false;
  for(let i=0;i<n;i++){
    const w=new Worker(URL.createObjectURL(new Blob([WC],{type:'application/javascript'})));
    ws.push(w);w.postMessage({challenge:CHALLENGE,difficulty:DIFFICULTY,startNonce:i,step:n});
    w.onmessage=e=>{if(done)return;done=true;ws.forEach(x=>x.terminate());submit(e.data.nonce,e.data.hash);};
  }
}

function submit(nonce,response){
  ss(${JSON.stringify(STRINGS.btn_verifying)});
  const fd=new FormData();
  fd.append('nonce',String(nonce));fd.append('response',response);
  fd.append('verify','true');fd.append('original_path',ORIG);
  fd.append('fp_score',String(lastScore));fd.append('fp_nonce',FP_NONCE);
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

  // 靜態資源
  if(url.pathname.match(/\.(png|jpg|jpeg|gif|webp|css|js|ico|svg|json|xml|rss|atom)$/)||
     url.pathname.startsWith("/albireo-dist/")) return next();

  // SEO bots
  if(BOT_AGENTS.some(b=>ua.includes(b))) return next();

  // ============================================================
  // Tor Exit Node 檢查（server-side，無法偽造）
  // CF-Connecting-IP 是 Cloudflare 加的，client 無法竄改
  // ============================================================
  const clientIP = request.headers.get("CF-Connecting-IP") || "";
  if(clientIP && await isTorExitNode(clientIP)){
    return new Response("Forbidden", { status: 403 });
  }

  // Server-side suspicion scoring
  let sus=0;
  const BOTS=["bot","crawler","spider","scraper","scrapy","python-requests","go-http-client","curl","wget","libwww","httpx"];
  if(BOTS.some(p=>ua.includes(p)))            sus+=10;
  if(!request.headers.get("Accept"))          sus+=5;
  if(!ua)                                     sus+=10;
  if(!request.headers.get("Accept-Language")) sus+=5;
  if(!request.headers.get("Sec-Fetch-Mode"))  sus+=5;
  if(sus>=10) return new Response("Forbidden",{status:403});

  const serverDiff=sus===0?1:DIFFICULTY;

  // Honeypot 路徑
  if(url.pathname.startsWith(HONEYPOT_PREFIX)){
    const token=url.pathname.slice(HONEYPOT_PREFIX.length);
    if(await verifyHoneypotToken(token)){
      const h=new Headers();
      h.append("Set-Cookie","albireo_bot=true; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400");
      return new Response("Not Found",{status:403,headers:h});
    }
    return new Response("Not Found",{status:404});
  }

  // Bot 黑名單
  if(cookie.includes("albireo_bot=true")) return new Response("Forbidden",{status:403});

  // Solved cookie
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

  // POST: PoW 驗證
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
      if(parts.length!==5)return new Response("Invalid Challenge",{status:403}); // FIX: 5 段
      const[ch,ts,diffStr,cookieFpNonce,sig]=parts;
      // FIX: 簽名涵蓋 fp_nonce
      if(!await verify(ch+'.'+ts+'.'+diffStr+'.'+cookieFpNonce,sig))return new Response("Invalid Signature",{status:403});
      const issued=parseInt(ts,10);
      if(isNaN(issued)||Date.now()-issued>CHALLENGE_TTL)return new Response("Challenge Expired",{status:403});
      const diff=parseInt(diffStr,10);
      if(isNaN(diff)||diff<1)return new Response("Invalid Difficulty",{status:403});
      if(!await checkPoW(ch,nonce,resp,diff))return new Response("POW Failed",{status:403});
      // FIX: 驗 fp_nonce（確認 JS 有跑、不是直接 POST）
      const clientFpNonce=fd.get("fp_nonce") as string||"";
      if(clientFpNonce!==cookieFpNonce)return new Response("Fingerprint Token Mismatch",{status:403});
      // FIX: 驗 fp_score（爬蟲如實回報高分就擋）
      const fpScore=parseInt(fd.get("fp_score") as string||"0",10);
      if(fpScore>=60)return new Response("Bot Detected",{status:403});
      // FIX: elapsedTime 驗證
      // 真實瀏覽器跑指紋偵測至少需要 300ms
      // 太快代表沒跑 JS 直接 POST
      const elapsed=parseInt(fd.get("elapsed") as string||"0",10);
      if(isNaN(elapsed)||elapsed<10)return new Response("Too Fast",{status:403});
      // 太慢也可疑（超過 5 分鐘，challenge 幾乎過期）
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
  const fpNonce=crypto.randomUUID().replace(/-/g,''); // FIX: session-bound fp_nonce
  const payload=rnd+'.'+ts+'.'+ds+'.'+fpNonce;       // FIX: 5 段，含 fp_nonce
  const sig=await sign(payload);
  const orig=safeRedirect(url.pathname+url.search+url.hash);
  const trap=await generateHoneypotToken();
  const h=new Headers();
  h.set("Content-Type","text/html");
  h.set("Cache-Control","private,no-cache,no-store,must-revalidate");
  h.set("Set-Cookie",`albireo_challenge=${encodeURIComponent(payload+'.'+sig)}; Path=/; HttpOnly; Secure; SameSite=Lax`);
  const html=GENERATE_HTML(rnd,orig,serverDiff,fpNonce); // FIX: 傳 fpNonce 給 HTML
  const injected=html.replace("</body>",
    `<div aria-hidden="true" style="position:absolute;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;"><a href="${HONEYPOT_PREFIX+trap}" rel="nofollow" tabindex="-1">.</a></div></body>`
  );
  return new Response(injected,{headers:h});
};
