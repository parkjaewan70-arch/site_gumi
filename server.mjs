import http from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {randomBytes,createHash,timingSafeEqual} from 'node:crypto';
import {mkdirSync,readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {valid} from './projection.mjs';
const root=dirname(fileURLToPath(import.meta.url));
const secret=()=>randomBytes(32).toString('base64url');const hash=s=>createHash('sha256').update(s).digest('hex');
const equal=(a,b)=>timingSafeEqual(Buffer.from(hash(a)),Buffer.from(hash(b)));
export function createApp({password,origin='http://localhost:3000',dataDir='./data',secure=true,clock=Date.now}={}){
 if(!password||password.length<16)throw Error('ADMIN_PASSWORD must have at least 16 characters');
 const publicOrigin=new URL(origin).origin;mkdirSync(dataDir,{recursive:true});const db=new DatabaseSync(resolve(dataDir,'control.sqlite'));
 db.exec(`PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS workers(id TEXT PRIMARY KEY,name TEXT NOT NULL,company TEXT NOT NULL,token_hash TEXT,invite_hash TEXT,invite_expires INTEGER,active INTEGER DEFAULT 0,lat REAL,lng REAL,accuracy REAL,observed INTEGER,received INTEGER,started INTEGER,ended INTEGER);CREATE TABLE IF NOT EXISTS settings(id TEXT PRIMARY KEY,value TEXT);`);
 const sessions=new Map(),attempts=new Map();
 const sweep=setInterval(()=>{const now=clock();db.prepare('UPDATE workers SET lat=NULL,lng=NULL,accuracy=NULL,observed=NULL,received=NULL WHERE received<?').run(now-86400000);for(const[k,v]of sessions)if(v<now)sessions.delete(k);for(const[k,v]of attempts)if(v.until<now)attempts.delete(k)},60000);sweep.unref();
 async function body(req){let s='';for await(const chunk of req){s+=chunk;if(s.length>16384)throw Object.assign(Error('요청이 너무 큽니다'),{status:413})}try{return JSON.parse(s||'{}')}catch{throw Object.assign(Error('JSON 형식을 확인하세요'),{status:400})}}
 function calibration(){const v=db.prepare('SELECT value FROM settings WHERE id=?').get('calibration');return v?JSON.parse(v.value):[]}
 const json=(res,status,b)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(b))};
 const server=http.createServer(async(req,res)=>{try{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');res.setHeader('Permissions-Policy','geolocation=(self)');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'");
 const path=new URL(req.url,'http://local').pathname;
 if(req.method==='POST'&&req.headers.origin!==publicOrigin)return json(res,403,{error:'허용되지 않은 출처'});
 const cookie=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('admin='))?.slice(6)||'';
 const admin=(sessions.get(hash(cookie))||0)>clock();
 const token=(req.headers.authorization||'').replace(/^Bearer /,'');
 const worker=token?db.prepare('SELECT * FROM workers WHERE token_hash=?').get(hash(token)):null;
 if(path==='/health')return json(res,200,{ok:true});
 if(path==='/api/login'&&req.method==='POST'){
 const ip=req.socket.remoteAddress;const a=attempts.get(ip)||{n:0,until:clock()+900000};if(a.n>=10&&a.until>clock())return json(res,429,{error:'잠시 후 다시 시도하세요'});
 const b=await body(req);if(typeof b.password!=='string'||!equal(b.password,password)){a.n++;attempts.set(ip,a);return json(res,401,{error:'비밀번호가 일치하지 않습니다'})}
 attempts.delete(ip);const s=secret();sessions.set(hash(s),clock()+8*3600000);res.setHeader('Set-Cookie',`admin=${s}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure?'; Secure':''}`);return json(res,200,{ok:true})}
 if(path==='/api/logout'&&req.method==='POST'){sessions.delete(hash(cookie));res.setHeader('Set-Cookie','admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return json(res,200,{ok:true})}
 if(path.startsWith('/api/admin/')){
 if(!admin)return json(res,401,{error:'관리자 로그인이 필요합니다'});
 if(path==='/api/admin/state'&&req.method==='GET'){const rows=db.prepare('SELECT id,name,company,active,lat,lng,accuracy,observed,received,started,ended FROM workers ORDER BY name').all().map(r=>({...r,lat:r.received>clock()-86400000?r.lat:null,lng:r.received>clock()-86400000?r.lng:null}));return json(res,200,{rows,calibration:calibration(),now:clock()})}
 if(path==='/api/admin/workers'&&req.method==='POST'){const b=await body(req);if(typeof b.name!=='string'||!b.name.trim()||typeof b.company!=='string'||!b.company.trim())return json(res,400,{error:'이름·소속을 입력하세요'});if(db.prepare('SELECT count(*) n FROM workers').get().n>=80)return json(res,409,{error:'80명 등록 한도입니다'});const id=randomBytes(12).toString('hex');const invite=secret();db.prepare('INSERT INTO workers(id,name,company,invite_hash,invite_expires) VALUES(?,?,?,?,?)').run(id,b.name.trim().slice(0,40),b.company.trim().slice(0,60),hash(invite),clock()+86400000);return json(res,201,{id,url:publicOrigin+'/worker.html#invite='+invite})}
 if(path==='/api/admin/invite'&&req.method==='POST'){const b=await body(req);const invite=secret();const r=db.prepare('UPDATE workers SET invite_hash=?,invite_expires=?,token_hash=NULL,active=0,lat=NULL,lng=NULL,accuracy=NULL,received=NULL,observed=NULL WHERE id=?').run(hash(invite),clock()+86400000,b.id||'');if(!r.changes)return json(res,404,{error:'근로자를 찾을 수 없습니다'});return json(res,200,{url:publicOrigin+'/worker.html#invite='+invite})}
 if(path==='/api/admin/remove'&&req.method==='POST'){const b=await body(req);db.prepare('DELETE FROM workers WHERE id=?').run(b.id||'');return json(res,200,{ok:true})}
 if(path==='/api/admin/calibration'&&req.method==='POST'){const b=await body(req);if(!valid(b.points))return json(res,400,{error:'유효한 3개 기준점을 입력하세요. 일직선은 사용할 수 없습니다'});db.prepare('INSERT INTO settings(id,value) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value').run('calibration',JSON.stringify(b.points));return json(res,200,{ok:true})}
 if(path==='/api/admin/qr'&&req.method==='POST'){const b=await body(req);const url=new URL(b.url);if(url.origin!==publicOrigin||url.pathname!=='/worker.html')return json(res,400,{error:'근로자 초대 주소만 허용합니다'});const {default:qr}=await import('qrcode');const svg=await qr.toString(url.href,{type:'svg',margin:4});res.writeHead(200,{'Content-Type':'image/svg+xml','Cache-Control':'no-store'});return res.end(svg)}
 }
 if(path==='/api/enroll'&&req.method==='POST'){const b=await body(req);if(typeof b.invite!=='string')return json(res,400,{error:'초대 링크를 확인하세요'});const r=db.prepare('SELECT * FROM workers WHERE invite_hash=? AND invite_expires>?').get(hash(b.invite),clock());if(!r)return json(res,401,{error:'초대가 만료되었거나 이미 사용되었습니다. 관리자에게 재발급을 요청하세요'});const t=secret();db.prepare('UPDATE workers SET token_hash=?,invite_hash=NULL,invite_expires=NULL WHERE id=?').run(hash(t),r.id);return json(res,200,{token:t,name:r.name,company:r.company})}
 if(path==='/api/me'&&req.method==='GET'){if(!worker)return json(res,401,{error:'개인 초대 QR로 등록하세요'});return json(res,200,{name:worker.name,company:worker.company})}
 if(path==='/api/location'&&req.method==='POST'){
 if(!worker)return json(res,401,{error:'유효한 근로자 인증이 필요합니다'});const b=await body(req);
 if(b.stop===true){db.prepare('UPDATE workers SET active=0,lat=NULL,lng=NULL,accuracy=NULL,received=NULL,observed=NULL,ended=? WHERE id=?').run(clock(),worker.id);return json(res,200,{ok:true})}
 if(b.consent!==true||![b.lat,b.lng,b.accuracy,b.observed].every(Number.isFinite)||Math.abs(b.lat)>90||Math.abs(b.lng)>180||b.accuracy<0||b.observed>clock()+60000||b.observed<clock()-120000)return json(res,400,{error:'유효한 최신 위치와 동의가 필요합니다'});
 if(worker.observed&&b.observed<worker.observed)return json(res,409,{error:'이전 위치는 반영하지 않습니다'});
 db.prepare('UPDATE workers SET active=1,lat=?,lng=?,accuracy=?,observed=?,received=?,started=CASE WHEN active=0 THEN ? ELSE started END,ended=NULL WHERE id=?').run(b.lat,b.lng,b.accuracy,b.observed,clock(),clock(),worker.id);return json(res,200,{ok:true,received:clock()})}
 if(path.startsWith('/api/'))return json(res,404,{error:'경로를 찾을 수 없습니다'});
 const files={'/':'dashboard.html','/dashboard.html':'dashboard.html','/worker.html':'worker.html','/dashboard.js':'dashboard.js','/worker.js':'worker.js','/common.css':'common.css','/site.jpg':'site.jpg','/manifest.webmanifest':'manifest.webmanifest','/icon.svg':'icon.svg','/sw.js':'sw.js','/projection.mjs':'../projection.mjs'};
 if(req.method!=='GET'||!files[path])return json(res,404,{error:'파일이 없습니다'});
 const f=files[path],ext=f.split('.').pop();const mime={html:'text/html; charset=utf-8',js:'text/javascript',mjs:'text/javascript',css:'text/css',jpg:'image/jpeg',svg:'image/svg+xml',webmanifest:'application/manifest+json'};res.writeHead(200,{'Content-Type':mime[ext]||'application/octet-stream','Cache-Control':'no-store'});res.end(readFileSync(resolve(root,'public',f)));
 }catch(e){json(res,e.status||500,{error:e.status?e.message:'서버 처리 실패. 서버 상태를 확인하세요.'})}});
 server.on('close',()=>{clearInterval(sweep);db.close()});return server;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){const app=createApp({password:process.env.ADMIN_PASSWORD,origin:process.env.PUBLIC_ORIGIN,dataDir:process.env.DATA_DIR,secure:process.env.COOKIE_SECURE!=='false'});app.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('관제 서버 시작 · 포트 '+(process.env.PORT||3000)))}
