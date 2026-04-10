const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();

const allowedOrigins = (process.env.CORS_ORIGIN || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
app.use(
    cors({
        origin: (origin, cb) => {
            if (!origin) return cb(null, true); // allow curl / server-to-server
            if (allowedOrigins.length === 0) return cb(null, true); // dev fallback
            if (allowedOrigins.includes(origin)) return cb(null, true);
            return cb(new Error('Not allowed by CORS'));
        }
    })
);
app.use(express.json());

function requireEnv(name) {
    const v = process.env[name];
    if (!v) throw new Error(`Missing required env var: ${name}`);
    return v;
}

function isValidEmail(email) {
    if (typeof email !== 'string') return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function parsePositiveInt(value) {
    const n = Number(value);
    if (!Number.isFinite(n)) return null;
    const i = Math.trunc(n);
    if (i <= 0) return null;
    return i;
}

function clampInt(n, min, max) {
    if (!Number.isFinite(n)) return null;
    const i = Math.trunc(n);
    if (i < min) return min;
    if (i > max) return max;
    return i;
}

function normalizeReservationMode(mode) {
    if (typeof mode !== 'string') return null;
    const m = mode.trim().toLowerCase();
    if (m === 'approval' || m === 'approval_required' || m === 'approve') return 'approval';
    if (m === 'instant' || m === 'auto') return 'instant';
    return null;
}

function authAdmin(req, res, next) {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
        return res.status(401).json({ error: 'Missing Authorization Bearer token' });
    }
    try {
        const payload = jwt.verify(token, requireEnv('JWT_SECRET'));
        if (payload?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
        req.user = payload;
        return next();
    } catch (e) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// --- 1. DB CONNECTION ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

async function queryOne(text, params) {
    const r = await pool.query(text, params);
    return r.rows[0] || null;
}

// --- 2. E-MAILOVÝ SERVIS ---
const transporter = process.env.SMTP_HOST
    ? nodemailer.createTransport({
          host: process.env.SMTP_HOST,
          port: Number(process.env.SMTP_PORT || 587),
          secure: String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true',
          auth: process.env.SMTP_USER
              ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
              : undefined
      })
    : nodemailer.createTransport({
          service: process.env.GMAIL_SERVICE || 'gmail',
          auth: process.env.GMAIL_USER ? { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS } : undefined
      });

async function sendMailSafe(options, label) {
    try {
        if (!transporter) return;
        // If transporter has no auth configured, nodemailer may still attempt to send; keep it explicit.
        if (!process.env.GMAIL_USER && !process.env.SMTP_HOST) return;
        await transporter.sendMail(options);
    } catch (e) {
        console.log(`${label || 'E-mail'} neodešel:`, e?.message || e);
    }
}

// --- 3. LOGIN ---
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body || {};
        if (typeof email !== 'string' || typeof password !== 'string') {
            return res.status(400).json({ error: 'Invalid payload' });
        }

        const adminEmail = requireEnv('ADMIN_EMAIL');
        const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
        const adminPassword = process.env.ADMIN_PASSWORD;

        if (email.trim().toLowerCase() !== adminEmail.trim().toLowerCase()) {
            return res.status(401).json({ error: 'Chybné údaje' });
        }

        let ok = false;
        if (adminPasswordHash) ok = await bcrypt.compare(password, adminPasswordHash);
        else if (adminPassword) ok = password === adminPassword;
        else return res.status(500).json({ error: 'Server auth misconfigured' });

        if (!ok) return res.status(401).json({ error: 'Chybné údaje' });

        const token = jwt.sign({ role: 'admin' }, requireEnv('JWT_SECRET'), {
            expiresIn: process.env.JWT_EXPIRES_IN || '12h'
        });
        return res.json({ token });
    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// --- 3b. CONTACT FORM ---
app.post('/contact', async (req, res) => {
    try {
        const { name, email, message, website } = req.body || {};

        // Honeypot field (bots often fill it). Frontend should keep it hidden and empty.
        if (typeof website === 'string' && website.trim().length > 0) {
            return res.json({ message: 'OK' });
        }

        const n = typeof name === 'string' ? name.trim() : '';
        const e = typeof email === 'string' ? email.trim() : '';
        const m = typeof message === 'string' ? message.trim() : '';
        if (n.length < 2) return res.status(400).json({ error: 'Invalid name' });
        if (!isValidEmail(e)) return res.status(400).json({ error: 'Invalid email' });
        if (m.length < 5) return res.status(400).json({ error: 'Invalid message' });

        const to = process.env.CONTACT_TO || process.env.RESERVATIONS_TO || process.env.GMAIL_USER;
        if (!to) return res.status(500).json({ error: 'Server mail misconfigured' });

        await sendMailSafe(
            {
                from: process.env.MAIL_FROM || '"Farnost Přeštice" <no-reply@example.com>',
                to,
                replyTo: e,
                subject: 'Zpráva z kontaktního formuláře',
                text: `Jméno: ${n}\nE-mail: ${e}\n\nZpráva:\n${m}\n`
            },
            'Kontakt'
        );

        return res.json({ message: 'Odesláno' });
    } catch (err) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// --- 4. NASTAVENÍ VZHLEDU ---
app.get('/settings', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM settings LIMIT 1');
        if (result.rows.length === 0) {
            return res.json({ 
                title: 'Římskokatolická farnost Přeštice', 
                background_color: '#F5F2EB' 
            });
        }
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/settings', authAdmin, async (req, res) => {
    try {
        const { title, background_color, backgroundColor } = req.body || {};
        const bg = typeof background_color === 'string' ? background_color : backgroundColor;
        if (typeof title !== 'string' || typeof bg !== 'string') {
            return res.status(400).json({ error: 'Invalid payload' });
        }

        await pool.query(
            `INSERT INTO settings (id, title, background_color)
             VALUES (1, $1, $2)
             ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, background_color = EXCLUDED.background_color`,
            [title, bg]
        );
        res.json({ message: 'Uloženo' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Chyba databáze' });
    }
});

// --- 5. AKCE ---
app.get('/events', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM events ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/events', authAdmin, async (req, res) => {
    try {
        const { time, name, is_reservable, capacity, reservation_mode } = req.body || {};
        if (typeof time !== 'string' || typeof name !== 'string') {
            return res.status(400).json({ error: 'Invalid payload' });
        }
        const cap = capacity == null ? 30 : clampInt(Number(capacity), 1, 500);
        const mode = reservation_mode == null ? 'approval' : normalizeReservationMode(reservation_mode);
        if (!cap) return res.status(400).json({ error: 'Invalid capacity' });
        if (!mode) return res.status(400).json({ error: 'Invalid reservation_mode' });

        await pool.query(
            'INSERT INTO events (time, name, is_reservable, capacity, reservation_mode) VALUES ($1, $2, $3, $4, $5)',
            [time.trim(), name.trim(), Boolean(is_reservable), cap, mode]
        );
        res.json({ message: 'Akce přidána' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/events/:id', authAdmin, async (req, res) => {
    try {
        const id = parsePositiveInt(req.params.id);
        if (!id) return res.status(400).json({ error: 'Invalid event id' });

        const { time, name, is_reservable, capacity, reservation_mode } = req.body || {};
        const cap = capacity == null ? null : clampInt(Number(capacity), 1, 500);
        const mode = reservation_mode == null ? null : normalizeReservationMode(reservation_mode);
        if (time != null && typeof time !== 'string') return res.status(400).json({ error: 'Invalid time' });
        if (name != null && typeof name !== 'string') return res.status(400).json({ error: 'Invalid name' });
        if (cap === 0) return res.status(400).json({ error: 'Invalid capacity' });
        if (reservation_mode != null && !mode) return res.status(400).json({ error: 'Invalid reservation_mode' });

        const updated = await pool.query(
            `UPDATE events
             SET time = COALESCE($1, time),
                 name = COALESCE($2, name),
                 is_reservable = COALESCE($3, is_reservable),
                 capacity = COALESCE($4, capacity),
                 reservation_mode = COALESCE($5, reservation_mode)
             WHERE id = $6
             RETURNING *`,
            [
                time == null ? null : time.trim(),
                name == null ? null : name.trim(),
                is_reservable == null ? null : Boolean(is_reservable),
                cap,
                mode,
                id
            ]
        );

        if (updated.rows.length === 0) return res.status(404).json({ error: 'Not found' });
        return res.json(updated.rows[0]);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.delete('/events/:id', authAdmin, async (req, res) => {
    try {
        const id = parsePositiveInt(req.params.id);
        if (!id) return res.status(400).json({ error: 'Invalid event id' });
        await pool.query('DELETE FROM events WHERE id = $1', [id]);
        return res.json({ message: 'Smazáno' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// --- 6. GALERIE ---
app.get('/gallery', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM gallery ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/gallery', authAdmin, async (req, res) => {
    try {
        const { url, desc } = req.body;
        if (typeof url !== 'string' || typeof desc !== 'string') {
            return res.status(400).json({ error: 'Invalid payload' });
        }
        await pool.query('INSERT INTO gallery (url, "desc") VALUES ($1, $2)', [url, desc]);
        res.json({ message: 'Fotka přidána' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/gallery/:id', authAdmin, async (req, res) => {
    try {
        const id = parsePositiveInt(req.params.id);
        if (!id) return res.status(400).json({ error: 'Invalid gallery id' });
        await pool.query('DELETE FROM gallery WHERE id = $1', [id]);
        return res.json({ message: 'Smazáno' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// --- 6b. AKTUALITY (NEWS) ---
app.get('/news', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM news ORDER BY date DESC, id DESC');
        return res.json(result.rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.post('/news', authAdmin, async (req, res) => {
    try {
        const { title, content, date } = req.body || {};
        if (typeof title !== 'string' || title.trim().length < 2) return res.status(400).json({ error: 'Invalid title' });
        if (typeof content !== 'string' || content.trim().length < 2) return res.status(400).json({ error: 'Invalid content' });
        if (date != null && typeof date !== 'string') return res.status(400).json({ error: 'Invalid date' });

        const r = await pool.query(
            'INSERT INTO news (title, content, date) VALUES ($1, $2, COALESCE($3, CURRENT_DATE)) RETURNING *',
            [title.trim(), content.trim(), date ? date.trim() : null]
        );
        return res.json(r.rows[0]);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.put('/news/:id', authAdmin, async (req, res) => {
    try {
        const id = parsePositiveInt(req.params.id);
        if (!id) return res.status(400).json({ error: 'Invalid news id' });
        const { title, content, date } = req.body || {};
        if (title != null && (typeof title !== 'string' || title.trim().length < 2)) return res.status(400).json({ error: 'Invalid title' });
        if (content != null && (typeof content !== 'string' || content.trim().length < 2)) return res.status(400).json({ error: 'Invalid content' });
        if (date != null && typeof date !== 'string') return res.status(400).json({ error: 'Invalid date' });

        const r = await pool.query(
            `UPDATE news
             SET title = COALESCE($1, title),
                 content = COALESCE($2, content),
                 date = COALESCE($3, date)
             WHERE id = $4
             RETURNING *`,
            [title == null ? null : title.trim(), content == null ? null : content.trim(), date == null ? null : date.trim(), id]
        );
        if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
        return res.json(r.rows[0]);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.delete('/news/:id', authAdmin, async (req, res) => {
    try {
        const id = parsePositiveInt(req.params.id);
        if (!id) return res.status(400).json({ error: 'Invalid news id' });
        await pool.query('DELETE FROM news WHERE id = $1', [id]);
        return res.json({ message: 'Smazáno' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// --- 7. REZERVACE ---
app.get('/reservations', authAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT r.*, e.name as event_name, e.time as event_time, e.reservation_mode as event_reservation_mode
            FROM reservations r 
            LEFT JOIN events e ON r.event_id = e.id 
            ORDER BY r.id DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/reservations', async (req, res) => {
    try {
        const { event_id, slot_id, group_name, people_count, email } = req.body || {};

        const eventId = parsePositiveInt(event_id);
        const slotId = slot_id == null ? null : parsePositiveInt(slot_id);
        const people = parsePositiveInt(people_count);
        if (!eventId) return res.status(400).json({ error: 'Invalid event_id' });
        if (typeof group_name !== 'string' || group_name.trim().length === 0) {
            return res.status(400).json({ error: 'Invalid group_name' });
        }
        if (!people) return res.status(400).json({ error: 'Invalid people_count' });
        if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });

        const ev = await queryOne('SELECT id, is_reservable, capacity, reservation_mode FROM events WHERE id = $1', [eventId]);
        if (!ev) return res.status(400).json({ error: 'Event not found' });
        if (ev.is_reservable === false) {
            return res.status(400).json({ error: 'This event is not reservable.' });
        }
        
        const cap = Number(ev.capacity || 30);
        if (people > cap) return res.status(400).json({ error: `Maximální kapacita je ${cap} osob.` });

        // Slot logic (optional). If event_slots exists and slot_id provided, enforce slot capacity.
        let finalSlotId = null;
        if (slotId) {
            const slot = await queryOne(
                'SELECT id, capacity, reserved_count FROM event_slots WHERE id = $1 AND event_id = $2',
                [slotId, eventId]
            );
            if (!slot) return res.status(400).json({ error: 'Slot not found' });
            const free = Number(slot.capacity) - Number(slot.reserved_count || 0);
            if (people > free) return res.status(400).json({ error: 'Slot is full' });
            finalSlotId = slot.id;
        }

        const mode = ev.reservation_mode || 'approval';
        const status = mode === 'instant' ? 'Rezervováno' : 'Čeká na schválení';

        await pool.query(
            'INSERT INTO reservations (event_id, slot_id, group_name, people_count, email, status) VALUES ($1, $2, $3, $4, $5, $6)',
            [eventId, finalSlotId, group_name.trim(), people, email.trim(), status]
        );

        await sendMailSafe(
            {
                from: process.env.MAIL_FROM || '"Farnost Přeštice" <no-reply@example.com>',
                to: email.trim(),
                subject: mode === 'instant' ? 'Potvrzení rezervace' : 'Přijetí žádosti o rezervaci',
                text:
                    mode === 'instant'
                        ? `Dobrý den,\n\nvaše rezervace na jméno "${group_name.trim()}" byla potvrzena.\n\nS pozdravem,\nŘKF Přeštice`
                        : `Dobrý den,\n\nvaše žádost o rezervaci na jméno "${group_name.trim()}" byla přijata a čeká na schválení administrátorem.\n\nS pozdravem,\nŘKF Přeštice`
            },
            'Rezervace klient'
        );

        res.json({ message: 'Rezervace uložena' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/reservations/:id/approve', authAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const rid = parsePositiveInt(id);
        if (!rid) return res.status(400).json({ error: 'Invalid reservation id' });

        const result = await pool.query(
            'UPDATE reservations SET status = $1 WHERE id = $2 RETURNING email, group_name',
            ['Schváleno', rid]
        );

        if (result.rows.length > 0) {
            await sendMailSafe(
                {
                    from: process.env.MAIL_FROM || '"Farnost Přeštice" <no-reply@example.com>',
                    to: result.rows[0].email,
                    subject: 'Rezervace schválena',
                    text: `Dobrý den,\n\nvaše rezervace pro "${result.rows[0].group_name}" byla schválena. Těšíme se na vaši návštěvu.\n\no. Mgr. Matej Ján Marek Buk`
                },
                'Rezervace schválení'
            );
        }

        res.json({ message: 'Schváleno' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- 7b. EVENT SLOTS (ADMIN) ---
app.get('/events/:id/slots', authAdmin, async (req, res) => {
    try {
        const id = parsePositiveInt(req.params.id);
        if (!id) return res.status(400).json({ error: 'Invalid event id' });
        const r = await pool.query('SELECT * FROM event_slots WHERE event_id = $1 ORDER BY start_time ASC', [id]);
        return res.json(r.rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.post('/events/:id/slots', authAdmin, async (req, res) => {
    try {
        const eventId = parsePositiveInt(req.params.id);
        if (!eventId) return res.status(400).json({ error: 'Invalid event id' });
        const { start_time, capacity } = req.body || {};
        if (typeof start_time !== 'string' || start_time.trim().length < 5) return res.status(400).json({ error: 'Invalid start_time' });
        const cap = capacity == null ? 30 : clampInt(Number(capacity), 1, 500);
        if (!cap) return res.status(400).json({ error: 'Invalid capacity' });

        const r = await pool.query(
            'INSERT INTO event_slots (event_id, start_time, capacity) VALUES ($1, $2, $3) RETURNING *',
            [eventId, start_time.trim(), cap]
        );
        return res.json(r.rows[0]);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.delete('/events/:eventId/slots/:slotId', authAdmin, async (req, res) => {
    try {
        const eventId = parsePositiveInt(req.params.eventId);
        const slotId = parsePositiveInt(req.params.slotId);
        if (!eventId || !slotId) return res.status(400).json({ error: 'Invalid id' });
        await pool.query('DELETE FROM event_slots WHERE id = $1 AND event_id = $2', [slotId, eventId]);
        return res.json({ message: 'Smazáno' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

const port = Number(process.env.PORT || 5000);
app.listen(port, () => {
    console.log(`SERVER BĚŽÍ NA PORTU ${port}`);
});