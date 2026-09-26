import {db,now} from './db.js';
// Run hourly. No demo data is ever inserted.
db.prepare("DELETE FROM public_messages WHERE created_at < datetime('now','-24 hours')").run();
db.prepare("DELETE FROM private_messages WHERE created_at < datetime('now','-30 days')").run();
db.prepare("DELETE FROM users WHERE last_message_at < datetime('now','-180 days') OR (last_message_at IS NULL AND last_seen_at < datetime('now','-180 days'))").run();
db.prepare('DELETE FROM muted_ips WHERE expire_at<=?').run(now());
console.log('Kelexy cleanup completed');
