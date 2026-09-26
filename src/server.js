import express from 'express';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { db, now, ip } from './db.js';

const app = express();
app.use(helmet()); app.use(express.json({ limit: '32kb' })); app.use(express.static('public'));
fs.mkdirSync(path.resolve('data/uploads'), { recursive: true });
const upload = multer({ dest: 'data/uploads/', limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (_, f, cb) => cb(null, /^image\/(png|jpeg|gif|webp)$/.test(f.mimetype)) });
const secret = process.env.JWT_SECRET || 'change-this-secret';
const issueToken = u => jwt.sign({ id: u.id, role: u.role }, secret, { expiresIn: '7d' });
const auth = (req, res, next) => { try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), secret); next(); } catch { res.status(401).json({ error: 'Nicht angemeldet' }); } };
const isMod = r => r === 'mod' || r === 'owner';
const mod = (req, res, next) => isMod(req.user?.role) ? next() : res.status(403).json({ error: 'Keine Berechtigung' });
const owner = (req, res, next) => req.user?.role === 'owner' ? next() : res.status(403).json({ error: 'Nur der Owner darf diese Einstellung ändern' });
const isMuted = (id, address) => { const u = db.prepare('SELECT muted_until FROM users WHERE id=?').get(id); return !!(db.prepare('SELECT 1 FROM muted_ips WHERE ip=? AND expire_at>?').get(address, now()) || (u?.muted_until && u.muted_until > now())); };
const setting = k => db.prepare('SELECT value FROM settings WHERE key=?').get(k)?.value;
const durations = role => role === 'owner' ? ['1h', '7d', '90d'] : ['1h', '7d'];

app.post('/api/auth/register', rateLimit({ windowMs: 60000, max: 10 }), (req, res) => {
  const parsed = z.object({ username: z.string().regex(/^[a-zA-Z0-9_-]{3,}$/), password: z.string().min(8), confirmPassword: z.string(), rules: z.literal(true) }).refine(x => x.password === x.confirmPassword, { path: ['confirmPassword'] }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Username, Passwort oder Regeln sind ungültig' });
  const address = ip(req); if (db.prepare('SELECT 1 FROM muted_ips WHERE ip=? AND expire_at>?').get(address, now())) return res.status(403).json({ error: 'Diese IP ist derzeit gemuted' });
  const previous = db.prepare('SELECT last_created FROM ip_registrations WHERE ip=?').get(address);
  if (previous?.last_created && Date.now() - Date.parse(previous.last_created) < 172800000) return res.status(429).json({ error: 'Von dieser IP ist erst nach 48 Stunden eine weitere Registrierung möglich' });
  const key = parsed.data.username.toLowerCase(); if (db.prepare('SELECT 1 FROM users WHERE username_key=?').get(key)) return res.status(409).json({ error: 'Username ist bereits vergeben' });
  const role = process.env.OWNER_USERNAME?.toLowerCase() === key ? 'owner' : 'user';
  const result = db.prepare('INSERT INTO users(username,username_key,password_hash,rules_accepted_at,role) VALUES(?,?,?,?,?)').run(parsed.data.username, key, bcrypt.hashSync(parsed.data.password, 12), now(), role);
  db.prepare('INSERT INTO ip_registrations(ip,count,last_created) VALUES(?,1,?) ON CONFLICT(ip) DO UPDATE SET count=count+1,last_created=excluded.last_created').run(address, now());
  const user = db.prepare('SELECT id,username,role FROM users WHERE id=?').get(result.lastInsertRowid); res.status(201).json({ token: issueToken(user), user });
});
app.post('/api/auth/login', (req, res) => { const u = db.prepare('SELECT * FROM users WHERE username_key=? AND deleted_at IS NULL').get(String(req.body.username || '').toLowerCase()); if (!u || !bcrypt.compareSync(req.body.password || '', u.password_hash)) return res.status(401).json({ error: 'Login fehlgeschlagen' }); db.prepare('UPDATE users SET last_seen_at=? WHERE id=?').run(now(), u.id); res.json({ token: issueToken(u), user: { id: u.id, username: u.username, role: u.role } }); });
app.get('/api/me', auth, (req, res) => res.json(db.prepare('SELECT id,username,role,allow_messages,language,muted_until FROM users WHERE id=?').get(req.user.id)));
app.get('/api/messages', auth, (req, res) => res.json(db.prepare('SELECT m.id,m.body,m.created_at,u.username,u.role FROM public_messages m JOIN users u ON u.id=m.user_id ORDER BY m.id DESC LIMIT 100').all().reverse()));
app.post('/api/messages', auth, (req, res) => {
  const address = ip(req); if (isMuted(req.user.id, address)) return res.status(403).json({ error: 'Du bist stummgeschaltet' });
  const lock = db.prepare('SELECT until,note FROM chat_locks WHERE id=1 AND until>?').get(now()); if (lock) return res.status(403).json({ error: `Der Chat ist gesperrt: ${lock.note}` });
  const body = String(req.body.body || '').trim(); if (!body || body.length > 2000) return res.status(400).json({ error: 'Ungültige Nachricht' });
  if (/https?:\/\/|www\./i.test(body) && (!isMod(req.user.role) || setting('links_allowed') !== 'true')) return res.status(400).json({ error: 'Links sind im Public Chat nicht erlaubt' });
  const slow = Number(setting('slow_mode') || 0), recent = db.prepare("SELECT created_at FROM public_messages WHERE user_id=? ORDER BY id DESC LIMIT 1").get(req.user.id); if (slow && recent && Date.now() - Date.parse(recent.created_at) < slow * 1000) return res.status(429).json({ error: `Slow Mode: Bitte ${slow} Sekunden warten` });
  const limit = Number(setting('spam_limit') || 0); if (limit && db.prepare("SELECT COUNT(*) n FROM message_events WHERE user_id=? AND created_at>datetime('now','-1 minute')").get(req.user.id).n >= limit) { const d = setting('spam_mute') || '1m'; const ms = { '1m': 60000, '5m': 300000, '10m': 600000 }[d] || 60000; db.prepare('UPDATE users SET muted_until=? WHERE id=?').run(new Date(Date.now() + ms).toISOString(), req.user.id); return res.status(429).json({ error: 'Spam-Limit überschritten. Du wurdest automatisch gemuted.' }); }
  db.prepare('INSERT INTO message_events(user_id) VALUES(?)').run(req.user.id); const r = db.prepare('INSERT INTO public_messages(user_id,body) VALUES(?,?)').run(req.user.id, body); db.prepare('UPDATE users SET last_message_at=?,last_seen_at=? WHERE id=?').run(now(), now(), req.user.id); res.status(201).json(db.prepare('SELECT m.id,m.body,m.created_at,u.username,u.role FROM public_messages m JOIN users u ON u.id=m.user_id WHERE m.id=?').get(r.lastInsertRowid));
});

app.get('/api/users/search', auth, (req, res) => res.json(db.prepare("SELECT id,username,role FROM users WHERE deleted_at IS NULL AND username_key LIKE ? AND id<>? ORDER BY username LIMIT 20").all(`${String(req.query.q || '').toLowerCase()}%`, req.user.id)));
app.post('/api/private-chats/:userId', auth, (req, res) => { const other = Number(req.params.userId); if (!other || other === req.user.id || !db.prepare('SELECT 1 FROM users WHERE id=? AND deleted_at IS NULL').get(other)) return res.status(404).json({ error: 'Benutzer nicht gefunden' }); const existing = db.prepare('SELECT id FROM private_chats WHERE (user_a=? AND user_b=?) OR (user_a=? AND user_b=?)').get(req.user.id, other, other, req.user.id); if (existing) return res.json(existing); const count = db.prepare('SELECT COUNT(*) n FROM private_chats WHERE user_a=? OR user_b=?').get(req.user.id, req.user.id).n; if (count >= 50) return res.status(400).json({ error: 'Maximal 50 private Chats' }); const r = db.prepare('INSERT INTO private_chats(user_a,user_b) VALUES(?,?)').run(Math.min(req.user.id, other), Math.max(req.user.id, other)); res.status(201).json({ id: r.lastInsertRowid }); });
app.get('/api/private-chats', auth, (req, res) => res.json(db.prepare('SELECT c.*, CASE WHEN c.user_a=? THEN ub.username ELSE ua.username END username, COALESCE(sa.pinned,0) pinned FROM private_chats c JOIN users ua ON ua.id=c.user_a JOIN users ub ON ub.id=c.user_b LEFT JOIN private_chat_settings sa ON sa.chat_id=c.id AND sa.user_id=? WHERE c.user_a=? OR c.user_b=? ORDER BY pinned DESC,c.updated_at DESC').all(req.user.id, req.user.id, req.user.id, req.user.id)));
app.post('/api/tickets', auth, (req, res) => { if (isMuted(req.user.id, ip(req))) return res.status(403).json({ error: 'Gemutete Benutzer können keine Tickets erstellen' }); if (db.prepare("SELECT COUNT(*) n FROM tickets WHERE status='open'").get().n >= 50) return res.status(429).json({ error: 'Es sind gerade zu viele Tickets offen. Bitte versuche es später erneut.' }); const last = db.prepare('SELECT created_at FROM tickets WHERE user_id=? ORDER BY id DESC LIMIT 1').get(req.user.id); if (last && Date.now() - Date.parse(last.created_at) < 259200000) return res.status(429).json({ error: 'Bitte warte 3 Tage nach der letzten Ticketerstellung.' }); const p = z.object({ subject:z.string().min(1).max(120), body:z.string().min(1).max(10000) }).safeParse(req.body); if (!p.success) return res.status(400).json({ error:'Ungültiges Ticket' }); const r=db.prepare('INSERT INTO tickets(user_id,subject,body) VALUES(?,?,?)').run(req.user.id,p.data.subject,p.data.body); res.status(201).json({ id:r.lastInsertRowid, notice:'Unnötige Tickets werden bestraft.' }); });
app.post('/api/tickets/:id/messages', auth, upload.single('image'), (req,res)=>{ const t=db.prepare('SELECT * FROM tickets WHERE id=?').get(req.params.id); if(!t || (t.user_id!==req.user.id && !isMod(req.user.role))) return res.status(404).json({error:'Ticket nicht gefunden'}); const r=db.prepare('INSERT INTO ticket_messages(ticket_id,user_id,body,image_path) VALUES(?,?,?,?)').run(t.id,req.user.id,String(req.body.body||''),req.file?.path||null); res.status(201).json({id:r.lastInsertRowid}); });
app.post('/api/settings', auth, (req,res)=>{ for(const [k,v] of Object.entries(req.body)) if(['allow_messages','language'].includes(k)) db.prepare(`UPDATE users SET ${k}=? WHERE id=?`).run(k==='allow_messages'?!!v:v,req.user.id); res.json({ok:true}); });
app.get('/api/admin/users', auth, owner, (req,res)=>res.json(db.prepare('SELECT id,username,role,muted_until,last_message_at FROM users WHERE deleted_at IS NULL ORDER BY username').all()));
app.post('/api/admin/settings', auth, owner, (req,res)=>{ const allowed={slow_mode:[2,5,10],spam_limit:[5,10,15],spam_mute:['1m','5m','10m']}; for(const [k,values] of Object.entries(allowed)) if(k in req.body && values.includes(req.body[k])) db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k,String(req.body[k])); if('links_allowed' in req.body) db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run('links_allowed',String(!!req.body.links_allowed)); res.json({ok:true}); });
app.post('/api/admin/clear-chat', auth, mod, (req,res)=>{ if(req.body.confirm!==true)return res.status(400).json({error:'Bestätigung erforderlich'}); db.prepare('DELETE FROM public_messages').run(); res.json({ok:true}); });
app.post('/api/admin/mute/:id', auth, mod, (req,res)=>{ const target=db.prepare('SELECT role FROM users WHERE id=?').get(req.params.id); if(!target||target.role==='owner'||(target.role==='mod'&&req.user.role!=='owner'))return res.status(403).json({error:'Dieser Benutzer kann nicht gemuted werden'}); if(!durations(req.user.role).includes(req.body.duration))return res.status(400).json({error:'Ungültige Mute-Dauer'}); const ms={'1h':3600000,'7d':604800000,'90d':7776000000}[req.body.duration]; const until=new Date(Date.now()+ms).toISOString(); db.prepare('UPDATE users SET muted_until=? WHERE id=?').run(until,req.params.id); db.prepare('INSERT INTO moderation_actions(target_user_id,moderator_id,kind,duration,note) VALUES(?,?,?,?,?)').run(req.params.id,req.user.id,'manual',req.body.duration,req.body.note||''); res.json({ok:true,until}); });
app.delete('/api/account', auth, (req,res)=>{ db.prepare('UPDATE users SET deleted_at=? WHERE id=?').run(now(),req.user.id); res.json({ok:true}); });
app.listen(process.env.PORT||3000,()=>console.log('Kelexy running'));
