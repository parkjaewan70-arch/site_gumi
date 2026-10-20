import test from 'node:test';import assert from 'node:assert/strict';import {mkdtempSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {createApp} from '../server.mjs';import {project,valid} from '../projection.mjs';
test('GPS ingestion, access separation, one-time QR, ordering, stop, renewal and capacity',async()=>{const dir=mkdtempSync(join(tmpdir(),'gumi-'));let now=Date.now();const origin='http://localhost:3000';const app=createApp({password:'test-password-1234567890',origin,dataDir:dir,secure:false,clock:()=>now});await new Promise(r=>app.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+app.address().port;let cookie='';
const call=async(path,body,{admin=false,token='',source=origin}={})=>{const r=await fetch(base+'/api/'+path,{method:body?'POST':'GET',headers:{...(body?{'Content-Type':'application/json',Origin:source}:{}),...(admin?{Cookie:cookie}:{}),...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});return {status:r.status,b:r.headers.get('content-type')?.includes('json')?await r.json():await r.text(),r}};
try{
assert.equal((await call('admin/state')).status,401);
assert.equal((await call('login',{password:'wrong'})).status,401);
assert.equal((await call('login',{password:'test-password-1234567890'},{source:'http://evil.test'})).status,403);
const login=await call('login',{password:'test-password-1234567890'});assert.equal(login.status,200);cookie=login.r.headers.get('set-cookie').split(';')[0];
const a=await call('admin/workers',{name:'검증근로자',company:'테스트소속'},{admin:true});assert.equal(a.status,201);const invite=new URL(a.b.url).hash.slice(8);
const qr=await call('admin/qr',{url:a.b.url},{admin:true});assert.equal(qr.status,200);assert.match(qr.b,/<svg/);
const enrolled=await call('enroll',{invite});assert.equal(enrolled.status,200);const token=enrolled.b.token;assert.equal((await call('enroll',{invite})).status,401);
assert.equal((await call('admin/state',undefined,{token})).status,401);
const refs=[{x:10,y:20,lat:36,lng:128},{x:90,y:20,lat:36,lng:128.002},{x:10,y:90,lat:35.998,lng:128}];assert.equal((await call('admin/calibration',{points:refs},{admin:true})).status,200);
const location={lat:36,lng:128,accuracy:5,observed:now,consent:true};assert.equal((await call('location',location)).status,401);assert.equal((await call('location',{...location,lat:91},{token})).status,400);assert.equal((await call('location',{...location,consent:false},{token})).status,400);assert.equal((await call('location',location,{token})).status,200);
let state=(await call('admin/state',undefined,{admin:true})).b;assert.equal(state.rows[0].name,'검증근로자');assert.equal(state.rows[0].active,1);assert.equal(state.rows[0].lat,36);assert.deepEqual(state.calibration,refs);
assert.equal((await call('location',{...location,observed:now-10},{token})).status,409);
now+=90000;state=(await call('admin/state',undefined,{admin:true})).b;assert(now-state.rows[0].received>60000);assert.equal(state.rows[0].active,1);
assert.equal((await call('location',{stop:true},{token})).status,200);state=(await call('admin/state',undefined,{admin:true})).b;assert.equal(state.rows[0].active,0);assert.equal(state.rows[0].lat,null);
await call('location',{...location,observed:now},{token});now+=86400001;const again=await call('login',{password:'test-password-1234567890'});cookie=again.r.headers.get('set-cookie').split(';')[0];state=(await call('admin/state',undefined,{admin:true})).b;assert.equal(state.rows[0].lat,null);
const renewal=await call('admin/invite',{id:a.b.id},{admin:true});assert.equal(renewal.status,200);assert.equal((await call('location',{stop:true},{token})).status,401);
// Multiple phones are distinct workers, even with identical names.
for(let i=1;i<80;i++){assert.equal((await call('admin/workers',{name:'동명이인',company:'협력사'+i},{admin:true})).status,201)}
assert.equal((await call('admin/workers',{name:'초과',company:'협력사'},{admin:true})).status,409);
assert.equal((await call('admin/state',undefined,{admin:true})).b.rows.length,80);
await call('admin/remove',{id:a.b.id},{admin:true});assert.equal((await call('admin/state',undefined,{admin:true})).b.rows.length,79);
await call('logout',{}, {admin:true});assert.equal((await call('admin/state',undefined,{admin:true})).status,401);
}finally{await new Promise(r=>app.close(r));rmSync(dir,{recursive:true,force:true})}});
test('affine projection respects three controls and midpoint and rejects degenerate controls',()=>{const r=[{x:10,y:20,lat:36,lng:128},{x:90,y:30,lat:36.0001,lng:128.002},{x:20,y:90,lat:35.998,lng:128.0002}];assert(valid(r));for(const p of r){const out=project(r,p.lat,p.lng);assert(Math.abs(out.x-p.x)<1e-6);assert(Math.abs(out.y-p.y)<1e-6)}const out=project(r,(r[0].lat+r[1].lat)/2,(r[0].lng+r[1].lng)/2);assert(Math.abs(out.x-50)<1e-6);assert(Math.abs(out.y-25)<1e-6);assert(!valid([r[0],r[0],r[2]]));assert.equal(project([],36,128),null)});
