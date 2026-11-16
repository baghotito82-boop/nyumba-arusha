import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import pg from 'pg';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const uploadDir = path.resolve(root, process.env.UPLOAD_DIR || './uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',').map(s=>s.trim()) || '*', credentials: false }));
app.use(express.json({ limit: '1mb' }));
app.use('/uploads', express.static(uploadDir, { maxAge: '7d' }));
const frontendDir = path.resolve(root, '../frontend');
app.use(express.static(frontendDir));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));

const storage = multer.diskStorage({
destination: (,__,cb)=>cb(null, uploadDir),
filename: (,file,cb)=>cb(null, ${Date.now()}-${randomUUID()}${path.extname(file.originalname).toLowerCase()})
});
const upload = multer({ storage, limits: { fileSize: 510241024 }, fileFilter: (_,f,cb)=>cb(null, /^image/(jpeg|png|webp)$/.test(f.mimetype)) });

async function q(text, params=[]) { return (await pool.query(text, params)).rows; }
function tokenFor(user){ return jwt.sign({ sub:user.id, role:user.role, email:user.email }, process.env.JWT_SECRET, { expiresIn:'2h' }); }
function auth(req,res,next){
try { const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) throw new Error(); req.user=jwt.verify(h.slice(7),process.env.JWT_SECRET); next(); }
catch { res.status(401).json({error:'Unauthorized'}); }
}
function admin(req,res,next){ if(req.user?.role!=='ADMIN') return res.status(403).json({error:'Admin only'}); next(); }
async function audit(user,action,type,id,metadata={}){ try{await q('INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES($1,$2,$3,$4,$5)',[user?.sub||null,action,type,id,metadata]);}catch{} }

app.get('/api/health',(_,res)=>res.json({ok:true,service:'Nyumba Arusha API'}));
app.post('/api/auth/register', async(req,res)=>{
const {email,password}=req.body||{};
if(!/^\S+@\S+.\S+$/.test(email||'') || !password || password.length<8) return res.status(400).json({error:'Email and password (8+ characters) required'});
const exists=await q('SELECT id FROM users WHERE email=$1',[email.toLowerCase()]); if(exists[0]) return res.status(409).json({error:'Email already registered'});
const hash=await bcrypt.hash(password,12); const rows=await q('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email,role',[email.toLowerCase(),hash]);
res.status(201).json({token:tokenFor(rows[0]),user:rows[0]});
});
app.delete('/api/auth/delete',auth,async(req,res)=>{ await q('DELETE FROM users WHERE id=$1',[req.user.sub]); res.json({ok:true}); });

app.post('/api/auth/login', async(req,res)=>{
const {email,password}=req.body||{}; const rows=await q('SELECT * FROM users WHERE email=$1',[String(email||'').toLowerCase()]);
if(!rows[0] || !(await bcrypt.compare(password||'',rows[0].password_hash))) return res.status(401).json({error:'Invalid credentials'});
res.json({token:tokenFor(rows[0]),user:{id:rows[0].id,email:rows[0].email,role:rows[0].role}});
});

app.get('/api/settings', async(_,res)=>res.json((await q('SELECT app_name,access_fee,airtel_number,mpesa_number,currency,payment_provider FROM settings WHERE id=true'))[0]));
app.put('/api/settings',auth,admin,async(req,res)=>{
const {access_fee,airtel_number,mpesa_number,payment_provider}=req.body||{};
if(!Number.isInteger(Number(access_fee))||Number(access_fee)<=0) return res.status(400).json({error:'Invalid access fee'});
const rows=await q('UPDATE settings SET access_fee=$1,airtel_number=$2,mpesa_number=$3,payment_provider=$4,updated_at=now() WHERE id=true RETURNING *',[Number(access_fee),String(airtel_number||''),String(mpesa_number||''),String(payment_provider||'manual')]);
await audit(req.user,'UPDATE_SETTINGS','settings','true',req.body); res.json(rows[0]);
});

app.get('/api/properties',async(req,res)=>{
const {q:term='',area='',minRent,maxRent}=req.query; const vals=[]; const where=["status='ACTIVE'"];
if(term){vals.push(%${term}%); where.push((title ILIKE $${vals.length} OR area ILIKE $${vals.length} OR description ILIKE $${vals.length}))}
if(area){vals.push(area); where.push(area=$${vals.length})}
if(minRent){vals.push(Number(minRent)); where.push(monthly_rent >= $${vals.length})}
if(maxRent){vals.push(Number(maxRent)); where.push(monthly_rent <= $${vals.length})}
const rows=await q(SELECT id,title,area,address_hint,monthly_rent,rooms,bathrooms,description,amenities,image_url,status,created_at FROM properties WHERE ${where.join(' AND ')} ORDER BY created_at DESC,vals);
res.json(rows);
});
app.get('/api/properties/:id',async(req,res)=>{const rows=await q('SELECT id,title,area,address_hint,monthly_rent,rooms,bathrooms,description,amenities,image_url,status,created_at FROM properties WHERE id=$1 AND status='ACTIVE'',[req.params.id]); if(!rows[0])return res.status(404).json({error:'Property not found'}); res.json(rows[0]);});
app.get('/api/properties/:id/contact',auth,async(req,res)=>{
const rows=await q(SELECT p.phone,p.whatsapp,p.landlord_name FROM properties p JOIN contact_access ca ON ca.property_id=p.id WHERE p.id=$1 AND ca.user_id=$2,[req.params.id,req.user.sub]);
if(!rows[0]) return res.status(402).json({error:'Contact locked',requiresPayment:true}); res.json(rows[0]);
});

app.post('/api/admin/properties',auth,admin,upload.single('image'),async(req,res)=>{
const {title,area,address_hint,monthly_rent,rooms,bathrooms,description,amenities,landlord_name,phone,whatsapp}=req.body;
if(!title||!area||!Number(monthly_rent)||!phone) return res.status(400).json({error:'title, area, monthly_rent and phone are required'});
const image_url=req.file?${process.env.PUBLIC_BASE_URL||''}/uploads/${req.file.filename}:null;
let am=[]; try{am=amenities?JSON.parse(amenities):[]}catch{}
const rows=await q(INSERT INTO properties(title,area,address_hint,monthly_rent,rooms,bathrooms,description,amenities,landlord_name,phone,whatsapp,image_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *,[title,area,address_hint||null,Number(monthly_rent),rooms?Number(rooms):null,bathrooms?Number(bathrooms):null,description||'',JSON.stringify(am),landlord_name||'',phone,whatsapp||'',image_url]);
await audit(req.user,'CREATE_PROPERTY','property',rows[0].id,{title}); res.status(201).json(rows[0]);
});
app.delete('/api/admin/properties/:id',auth,admin,async(req,res)=>{await q("UPDATE properties SET status='HIDDEN',updated_at=now() WHERE id=$1",[req.params.id]);await audit(req.user,'HIDE_PROPERTY','property',req.params.id);res.json({ok:true});});
app.get('/api/admin/properties',auth,admin,async(_,res)=>res.json(await q('SELECT * FROM properties ORDER BY created_at DESC')));

app.post('/api/payments/create',auth,async(req,res)=>{
const {property_id,payer_phone}=req.body||{};
const s=(await q('SELECT * FROM settings WHERE id=true'))[0];
const p=(await q('SELECT id FROM properties WHERE id=$1 AND status='ACTIVE'',[property_id]))[0];
if(!p)return res.status(404).json({error:'Property not found'});
const existing=(await q("SELECT * FROM payments WHERE user_id=$1 AND property_id=$2 AND status='SUCCESS' LIMIT 1",[req.user.sub,property_id]))[0];
if(existing)return res.json({status:'SUCCESS',payment_id:existing.id,alreadyPaid:true});
const reference=NA-${Date.now()}-${randomUUID().slice(0,8)};
const rows=await q('INSERT INTO payments(user_id,property_id,amount,provider,provider_reference,payer_phone) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,amount,provider,provider_reference,status',[req.user.sub,property_id,s.access_fee,s.payment_provider,reference,payer_phone||null]);
const payment=rows[0];
// Provider-specific request is deliberately abstract: exact gateway credentials/endpoints are merchant-specific.
res.status(201).json({payment, instructions:{fee:s.access_fee,airtel_number:s.airtel_number,mpesa_number:s.mpesa_number,provider:s.payment_provider,reference}});
});

async function grantAccess(paymentId){
const rows=await q('SELECT * FROM payments WHERE id=$1',[paymentId]); if(!rows[0])throw new Error('payment not found');
const p=rows[0]; if(p.status!=='SUCCESS')return;
await q('INSERT INTO contact_access(user_id,property_id,payment_id) VALUES($1,$2,$3) ON CONFLICT(user_id,property_id) DO NOTHING',[p.user_id,p.property_id,p.id]);
}
app.post('/api/payments/webhook',async(req,res)=>{
const secret=req.headers['x-webhook-secret']; if(process.env.PAYMENT_WEBHOOK_SECRET && secret!==process.env.PAYMENT_WEBHOOK_SECRET) return res.status(401).json({error:'Invalid webhook secret'});
const {provider_reference,status,amount,provider,raw}=req.body||{};
if(!provider_reference)return res.status(400).json({error:'provider_reference required'});
const p=(await q('SELECT * FROM payments WHERE provider_reference=$1',[provider_reference]))[0]; if(!p)return res.status(404).json({error:'Payment not found'});
const validAmount=Number(amount)===p.amount; const normalized=['SUCCESS','FAILED','REVERSED','REFUNDED','PENDING'].includes(status)?status:'PENDING';
if(normalized==='SUCCESS'&&!validAmount)return res.status(400).json({error:'Amount mismatch'});
await q('UPDATE payments SET status=$1,provider=COALESCE($2,provider),raw_response=$3,updated_at=now() WHERE id=$4',[normalized,provider||null,JSON.stringify(raw||req.body),p.id]);
if(normalized==='SUCCESS')await grantAccess(p.id);
res.json({ok:true});
});

// Development/admin approval endpoint. Disable by not exposing it publicly in production.
app.post('/api/admin/payments/:id/approve',auth,admin,async(req,res)=>{const p=(await q('SELECT * FROM payments WHERE id=$1',[req.params.id]))[0];if(!p)return res.status(404).json({error:'Not found'});await q("UPDATE payments SET status='SUCCESS',updated_at=now() WHERE id=$1",[p.id]);await grantAccess(p.id);await audit(req.user,'APPROVE_PAYMENT','payment',p.id);res.json({ok:true});});
app.get('/api/admin/payments',auth,admin,async(,res)=>res.json(await q('SELECT p.*,u.email FROM payments p LEFT JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC')));
app.get('/api/admin/stats',auth,admin,async(,res)=>{const a=await q("SELECT count()::int c FROM properties WHERE status='ACTIVE'");const b=await q("SELECT count()::int c FROM payments WHERE status='SUCCESS'");const c=await q("SELECT COALESCE(sum(amount),0)::int total FROM payments WHERE status='SUCCESS'");res.json({properties:a[0].c,payments:b[0].c,revenue:c[0].total});});

app.get('/', (_,res)=>res.sendFile(path.join(frontendDir,'index.html')));

async function bootstrap(){
const adminEmail=process.env.ADMIN_EMAIL?.toLowerCase(); const adminPass=process.env.ADMIN_PASSWORD;
if(adminEmail&&adminPass){const hash=await bcrypt.hash(adminPass,12); await q(INSERT INTO users(email,password_hash,role) VALUES($1,$2,'ADMIN') ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash,role='ADMIN',[adminEmail,hash]);}
const port=Number(process.env.PORT||8080); app.listen(port,()=>console.log(Nyumba Arusha API listening on ${port}));
}
bootstrap().catch(e=>{console.error(e);process.exit(1)});

