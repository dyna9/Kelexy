import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
const dataDir = path.resolve('data'); fs.mkdirSync(dataDir, {recursive:true});
export const db = new Database(path.join(dataDir, 'kelexy.sqlite'));
db.pragma('foreign_keys = ON');
db.exec(fs.readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));
export const now = () => new Date().toISOString();
export const ip = req => (req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '').replace(/^::ffff:/,'');
