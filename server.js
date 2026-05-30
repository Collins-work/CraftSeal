const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');

try {
    require('dotenv').config();
} catch (e) {
}



const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'craftseal-data.json');
const PORT = process.env.PORT || 3001;
const RP_ID = process.env.RP_ID || '127.0.0.1';
const RP_NAME = process.env.RP_NAME || 'Craft Seal';
const ORIGIN = process.env.ORIGIN || `http://127.0.0.1:${PORT}`;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
};

function readData() {
    try {
        const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
        return {
            users: [],
            artisans: [],
            jobs: [],
            bids: [],
            reviews: [],
            notifications: [],
            chats: [],
            authSessions: {},
            passkeys: [],
            paymentIntents: [],
            ...data,
        };
    } catch (e) {
        return { users: [], artisans: [], jobs: [], bids: [], reviews: [], notifications: [], chats: [], authSessions: {}, passkeys: [], paymentIntents: [] };
    }
}

function writeData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}


async function initializePersistence() {
    return;
}

function nowLabel() { return 'Just now'; }
function nextId(items) { return items.reduce((m, i) => Math.max(m, Number(i.id) || 0), 0) + 1; }

let clients = [];
function broadcast(state) {
    const payload = `data: ${JSON.stringify({ type: 'state', state })}\n\n`;
    clients = clients.filter((res) => {
        try { res.write(payload); return true; } catch (e) { return false; }
    });
}

function sendJson(res, statusCode, data) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(data));
}

function parseBody(req) {
    return new Promise((resolve) => { let raw = ''; req.on('data', c => raw += c); req.on('end', () => { if (!raw) return resolve({}); try { resolve(JSON.parse(raw)); } catch (e) { resolve({}); } }); });
}

function serveFile(res, filePath) {
    fs.readFile(filePath, (err, content) => {
        if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Not found'); return; }
        const ext = path.extname(filePath).toLowerCase();
        res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
        res.end(content);
    });
}

function publicPath(urlPath) {
    const normalized = decodeURIComponent(urlPath).replace(/^\/+/, '');
    const resolved = path.normalize(path.join(ROOT, normalized));
    if (!resolved.startsWith(ROOT)) return null;
    return resolved;
}

function computeRating(reviews) {
    if (!reviews || reviews.length === 0) return null;
    const avg = reviews.reduce((s, r) => s + (Number(r.rating) || 0), 0) / reviews.length;
    return Math.round((avg + Number.EPSILON) * 10) / 10;
}

function createNotification(state, text, icon = '💬') {
    const note = { id: nextId(state.notifications), icon, text, time: nowLabel(), unread: true };
    state.notifications.unshift(note);
    return note;
}

function publicUser(user) {
    if (!user) return null;
    const { passwordHash, passwordSalt, ...rest } = user;
    return rest;
}

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
    return { salt, hash };
}

function verifyPassword(password, salt, hash) {
    const candidate = crypto.scryptSync(String(password), salt, 64);
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), candidate);
}

function createSession(state, userId) {
    const token = crypto.randomBytes(24).toString('hex');
    state.authSessions[token] = { userId, createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS };
    return token;
}

function getSessionToken(req) {
    const cookie = req.headers.cookie || '';
    return cookie.split(';').map((part) => part.trim()).find((part) => part.startsWith('craftseal_session='))?.split('=')[1] || null;
}

function getUserFromRequest(state, req) {
    const token = getSessionToken(req);
    if (!token) return null;
    const session = state.authSessions[token];
    if (!session || session.expiresAt < Date.now()) return null;
    return state.users.find((user) => Number(user.id) === Number(session.userId)) || null;
}

function setSessionCookie(res, token) {
    res.setHeader('Set-Cookie', `craftseal_session=${token}; HttpOnly; Path=/; Max-Age=${60 * 60 * 24 * 7}; SameSite=Lax${PORT === 3001 ? '' : '; Secure'}`);
}

function clearSessionCookie(res) {
    res.setHeader('Set-Cookie', 'craftseal_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
}

function findUserByEmail(state, email) {
    const normalized = normalizeEmail(email);
    return state.users.find((user) => normalizeEmail(user.email) === normalized) || null;
}

function attachArtisanState(artisan, reviews) {
    const artisanReviews = reviews.filter((review) => Number(review.artisan_id) === Number(artisan.id));
    const rating = artisanReviews.length
        ? Math.round((artisanReviews.reduce((sum, review) => sum + Number(review.rating || 0), 0) / artisanReviews.length) * 10) / 10
        : null;
    return {
        ...artisan,
        rating,
        reviewCount: artisanReviews.length,
    };
}

const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    const url = new URL(req.url, `http://${req.headers.host}`);
    const state = readData();
    const currentUser = getUserFromRequest(state, req);


    if (url.pathname === '/api/state' && req.method === 'GET') {
        sendJson(res, 200, {
            ...state,
            users: state.users.map(publicUser),
            artisans: state.artisans.map((artisan) => attachArtisanState(artisan, state.reviews)),
            me: publicUser(currentUser),
        });
        return;
    }

    if (url.pathname === '/api/me' && req.method === 'GET') {
        sendJson(res, 200, { user: publicUser(currentUser) });
        return;
    }

    if (url.pathname === '/api/auth/register' && req.method === 'POST') {
        const body = await parseBody(req);
        const email = normalizeEmail(body.email);
        if (!email || !body.password || !body.fullName || !body.role) return sendJson(res, 400, { error: 'Missing auth fields' });
        if (findUserByEmail(state, email)) return sendJson(res, 409, { error: 'Email already registered' });
        const password = hashPassword(body.password);
        const user = {
            id: nextId(state.users),
            email,
            fullName: body.fullName,
            role: body.role,
            phone: body.phone || '',
            location: body.location || '',
            address: body.address || '',
            businessName: body.businessName || '',
            created_at: new Date().toISOString(),
            passwordSalt: password.salt,
            passwordHash: password.hash,
            passkeys: [],
        };
        state.users.push(user);
        if (body.role === 'artisan') {
            const artisan = {
                id: nextId(state.artisans),
                user_id: user.id,
                fullName: body.fullName,
                email,
                location: body.location || '',
                address: body.address || '',
                trade: body.trade || '',
                skills: Array.isArray(body.skills) ? body.skills : [],
                rating: null,
                reviewCount: 0,
                jobsDone: 0,
                available: true,
            };
            state.artisans.push(artisan);
        }
        const session = createSession(state, user.id);
        writeData(state); broadcast(state);
        setSessionCookie(res, session);
        sendJson(res, 201, { user: publicUser(user) });
        return;
    }

    if (url.pathname === '/api/auth/login' && req.method === 'POST') {
        const body = await parseBody(req);
        const user = findUserByEmail(state, body.email);
        if (!user || !body.password || !verifyPassword(body.password, user.passwordSalt, user.passwordHash)) return sendJson(res, 401, { error: 'Invalid credentials' });
        const session = createSession(state, user.id);
        writeData(state);
        setSessionCookie(res, session);
        sendJson(res, 200, { user: publicUser(user) });
        return;
    }

    if (url.pathname === '/api/auth/logout' && req.method === 'POST') {
        const token = getSessionToken(req);
        if (token) delete state.authSessions[token];
        writeData(state);
        clearSessionCookie(res);
        sendJson(res, 200, { ok: true });
        return;
    }

    if (url.pathname === '/api/auth/webauthn/register/options' && req.method === 'POST') {
        if (!currentUser) return sendJson(res, 401, { error: 'Login required' });
        const existing = state.passkeys.filter((cred) => Number(cred.userId) === Number(currentUser.id)).map((cred) => ({ id: cred.credentialID, type: 'public-key', transports: cred.transports || ['internal'] }));
        const options = await generateRegistrationOptions({
            rpName: RP_NAME,
            rpID: RP_ID,
            userID: String(currentUser.id),
            userName: currentUser.email,
            userDisplayName: currentUser.fullName || currentUser.email,
            excludeCredentials: existing,
            authenticatorSelection: { userVerification: 'preferred', residentKey: 'preferred', authenticatorAttachment: 'platform' },
        });
        state.authSessions[`webauthn:${currentUser.id}`] = { challenge: options.challenge, type: 'register', userId: currentUser.id, createdAt: Date.now(), expiresAt: Date.now() + 5 * 60 * 1000 };
        writeData(state);
        sendJson(res, 200, { options });
        return;
    }

    if (url.pathname === '/api/auth/webauthn/register/verify' && req.method === 'POST') {
        if (!currentUser) return sendJson(res, 401, { error: 'Login required' });
        const body = await parseBody(req);
        const challengeRecord = state.authSessions[`webauthn:${currentUser.id}`];
        if (!challengeRecord || challengeRecord.expiresAt < Date.now()) return sendJson(res, 400, { error: 'Passkey challenge expired' });
        const verification = await verifyRegistrationResponse({
            response: body.response,
            expectedChallenge: challengeRecord.challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
            requireUserVerification: true,
        });
        if (!verification.verified) return sendJson(res, 400, { error: 'Passkey registration failed' });
        const { registrationInfo } = verification;
        state.passkeys.push({
            userId: currentUser.id,
            credentialID: isoBase64URL.fromBuffer(registrationInfo.credentialID),
            publicKey: registrationInfo.credentialPublicKey,
            counter: registrationInfo.counter,
            transports: body.transports || ['internal'],
            createdAt: new Date().toISOString(),
        });
        const user = state.users.find((item) => Number(item.id) === Number(currentUser.id));
        if (user) user.passkeys = state.passkeys.filter((cred) => Number(cred.userId) === Number(user.id)).map((cred) => ({ credentialID: cred.credentialID, counter: cred.counter, transports: cred.transports }));
        delete state.authSessions[`webauthn:${currentUser.id}`];
        writeData(state);
        sendJson(res, 200, { verified: true });
        return;
    }

    if (url.pathname === '/api/auth/webauthn/login/options' && req.method === 'POST') {
        const body = await parseBody(req);
        const user = findUserByEmail(state, body.email);
        if (!user) return sendJson(res, 404, { error: 'User not found' });
        const credentials = state.passkeys.filter((cred) => Number(cred.userId) === Number(user.id)).map((cred) => ({ id: cred.credentialID, type: 'public-key', transports: cred.transports || ['internal'] }));
        const options = await generateAuthenticationOptions({
            rpID: RP_ID,
            userVerification: 'required',
            allowCredentials: credentials,
        });
        state.authSessions[`webauthn-login:${user.id}`] = { challenge: options.challenge, type: 'login', userId: user.id, createdAt: Date.now(), expiresAt: Date.now() + 5 * 60 * 1000 };
        writeData(state);
        sendJson(res, 200, { options, user: publicUser(user) });
        return;
    }

    if (url.pathname === '/api/auth/webauthn/login/verify' && req.method === 'POST') {
        const body = await parseBody(req);
        const user = state.users.find((item) => Number(item.id) === Number(body.userId));
        if (!user) return sendJson(res, 404, { error: 'User not found' });
        const challengeRecord = state.authSessions[`webauthn-login:${user.id}`];
        if (!challengeRecord || challengeRecord.expiresAt < Date.now()) return sendJson(res, 400, { error: 'Passkey challenge expired' });
        const credential = state.passkeys.find((cred) => Number(cred.userId) === Number(user.id) && cred.credentialID === body.credentialID);
        if (!credential) return sendJson(res, 400, { error: 'Credential not found' });
        const verification = await verifyAuthenticationResponse({
            response: body.response,
            expectedChallenge: challengeRecord.challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
            credential: {
                id: credential.credentialID,
                publicKey: credential.publicKey,
                counter: credential.counter,
                transports: credential.transports || ['internal'],
            },
            requireUserVerification: true,
        });
        if (!verification.verified) return sendJson(res, 400, { error: 'Passkey login failed' });
        credential.counter = verification.authenticationInfo.newCounter;
        user.passkeys = state.passkeys.filter((item) => Number(item.userId) === Number(user.id)).map((item) => ({ credentialID: item.credentialID, counter: item.counter, transports: item.transports }));
        const session = createSession(state, user.id);
        delete state.authSessions[`webauthn-login:${user.id}`];
        writeData(state);
        setSessionCookie(res, session);
        sendJson(res, 200, { user: publicUser(user), verified: true });
        return;
    }


    if (url.pathname === '/api/events' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'Access-Control-Allow-Origin': '*' });
        res.write('\n'); clients.push(res); req.on('close', () => { clients = clients.filter(c => c !== res); }); return;
    }


    if (url.pathname === '/api/users' && req.method === 'POST') {
        const body = await parseBody(req);
        if (!body || !body.email || !body.role) return sendJson(res, 400, { error: 'Missing user email or role' });
        const user = { id: nextId(state.users), email: body.email, name: body.fullName || body.name || '', role: body.role, location: body.location || '', address: body.address || '', created_at: new Date().toISOString() };
        state.users.push(user);
        if (body.role === 'artisan') {
            const artisan = { id: nextId(state.artisans), user_id: user.id, fullName: user.name, email: user.email, location: body.location || '', address: body.address || '', trade: body.trade || '', skills: body.skills || [], rating: null, reviewCount: 0, jobsDone: 0, available: true };
            state.artisans.push(artisan);
        }
        writeData(state); broadcast(state);
        sendJson(res, 201, { user, state }); return;
    }


    if (url.pathname === '/api/reviews' && req.method === 'POST') {
        const body = await parseBody(req);
        if (!body || !body.artisan_id || !body.user_id || !body.rating) return sendJson(res, 400, { error: 'Missing review fields' });
        const review = { id: nextId(state.reviews), artisan_id: Number(body.artisan_id), user_id: Number(body.user_id), rating: Number(body.rating), text: body.text || '', created_at: new Date().toISOString() };
        state.reviews.unshift(review);

        const artisanReviews = state.reviews.filter(r => Number(r.artisan_id) === Number(body.artisan_id));
        const art = state.artisans.find(a => Number(a.id) === Number(body.artisan_id));
        if (art) { art.rating = computeRating(artisanReviews); art.reviewCount = artisanReviews.length; }
        createNotification(state, `New review for ${art ? art.fullName : 'an artisan'}`);
        writeData(state); broadcast(state); sendJson(res, 201, { review, state }); return;
    }


    if (url.pathname === '/api/bids' && req.method === 'POST') {
        const body = await parseBody(req);
        if (!body || !body.job_id || !body.artisan_id || !body.amount) return sendJson(res, 400, { error: 'Missing bid fields' });
        const bid = { id: nextId(state.bids), job_id: Number(body.job_id), artisan_id: Number(body.artisan_id), amount: Number(body.amount), message: body.message || '', created_at: new Date().toISOString() };
        state.bids.unshift(bid);
        createNotification(state, `New bid on job #${bid.job_id}`);
        writeData(state); broadcast(state); sendJson(res, 201, { bid, state }); return;
    }


    if (url.pathname === '/api/jobs' && req.method === 'POST') {
        const body = await parseBody(req);
        if (!body || !body.title || !body.user_id) return sendJson(res, 400, { error: 'Missing job fields' });
        const job = { id: nextId(state.jobs), title: body.title, user_id: Number(body.user_id), cat: body.cat || 'all', status: 'open', location: body.location || '', budget: body.budget || '', date: new Date().toISOString(), bids: 0, desc: body.desc || '' };
        state.jobs.unshift(job);
        createNotification(state, `New job posted: ${job.title}`);
        writeData(state); broadcast(state); sendJson(res, 201, { job, state }); return;
    }


    if (url.pathname.startsWith('/api/jobs/') && req.method === 'PATCH') {
        const id = Number(url.pathname.split('/')[3]);
        const body = await parseBody(req);
        const job = state.jobs.find(j => Number(j.id) === id);
        if (!job) return sendJson(res, 404, { error: 'Job not found' });
        Object.assign(job, body.job || body);
        writeData(state); broadcast(state); sendJson(res, 200, { job, state }); return;
    }


    if (url.pathname === '/api/notifications' && req.method === 'POST') {
        const body = await parseBody(req);
        const note = createNotification(state, body.text || 'Notification', body.icon || '💬');
        writeData(state); broadcast(state); sendJson(res, 201, { notification: note, state }); return;
    }

    if (url.pathname.startsWith('/api/notifications/') && url.pathname.endsWith('/read') && req.method === 'PATCH') {
        const id = Number(url.pathname.split('/')[3]);
        const note = state.notifications.find(n => Number(n.id) === id);
        if (!note) return sendJson(res, 404, { error: 'Not found' });
        note.unread = false; writeData(state); broadcast(state); sendJson(res, 200, { notification: note, state }); return;
    }


    if (url.pathname === '/api/payments/init' && req.method === 'POST') {
        const body = await parseBody(req);
        const reference = `CS-${Date.now()}`;
        const amount = Number(body.amount || body.job?.budget || 0) || 0;
        if (amount <= 0) return sendJson(res, 400, { error: 'Missing payment amount' });

        const checkout_url = process.env.KORAPAY_CHECKOUT_URL
            ? `${process.env.KORAPAY_CHECKOUT_URL}?reference=${encodeURIComponent(reference)}`
            : `https://checkout.korapay.com/pay?reference=${encodeURIComponent(reference)}`;

        state.paymentIntents.unshift({
            id: nextId(state.paymentIntents),
            reference,
            amount,
            currency: 'NGN',
            status: 'initialized',
            jobId: body.jobId || null,
            userId: currentUser?.id || null,
            provider: 'korapay',
            tokenized: true,
            createdAt: new Date().toISOString(),
        });

        createNotification(state, `Payment started for ${body.job?.title || 'a job'}`);
        writeData(state); broadcast(state);
        sendJson(res, 200, {
            reference,
            amount,
            currency: 'NGN',
            checkout_url,
            provider: 'korapay',
            tokenized: true,
            state,
        });
        return;
    }


    if (url.pathname === '/api/chats' && req.method === 'GET') {

        const q = Object.fromEntries(url.searchParams.entries());
        let chats = Array.isArray(state.chats) ? state.chats : [];
        if (q.job_id) chats = chats.filter(c => Number(c.job_id) === Number(q.job_id));
        if (q.user_id) chats = chats.filter(c => Number(c.user_id) === Number(q.user_id));
        if (q.artisan_id) chats = chats.filter(c => Number(c.artisan_id) === Number(q.artisan_id));
        sendJson(res, 200, { chats, state }); return;
    }

    if (url.pathname === '/api/chats' && req.method === 'POST') {
        const body = await parseBody(req);
        if (!body || (!body.job_id && !body.chatId) || !body.sender_id || !body.text) return sendJson(res, 400, { error: 'Missing chat fields' });
        let chat = null;
        if (body.chatId) chat = state.chats.find(c => Number(c.id) === Number(body.chatId));
        if (!chat) {

            chat = { id: nextId(state.chats || []), job_id: Number(body.job_id), user_id: Number(body.user_id || 0), artisan_id: Number(body.artisan_id || 0), messages: [] };
            state.chats = state.chats || [];
            state.chats.unshift(chat);
        }
        const msg = { id: nextId(chat.messages || []), sender_id: Number(body.sender_id), text: String(body.text || ''), time: nowLabel() };
        chat.messages = chat.messages || [];
        chat.messages.push(msg);
        createNotification(state, `New message in job ${chat.job_id}`);
        writeData(state); broadcast(state); sendJson(res, 201, { chat, msg, state }); return;
    }


    if (url.pathname === '/' || url.pathname === '/landing' || url.pathname === '/craftseal-landing.html') {
        serveFile(res, path.join(ROOT, 'craftseal-landing.html'));
        return;
    }
    if (url.pathname === '/app' || url.pathname === '/craftseal-app' || url.pathname === '/craftseal-app.html' || url.pathname.startsWith('/app/')) {
        serveFile(res, path.join(ROOT, 'craftseal-app.html'));
        return;
    }
    const filePath = publicPath(url.pathname); if (filePath && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) { serveFile(res, filePath); return; }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Not found');
});

function probeExistingServer(port) {
    return new Promise((resolve) => {
        const req = http.get({ hostname: '127.0.0.1', port, path: '/api/state', timeout: 1500 }, (res) => {
            resolve(res.statusCode >= 200 && res.statusCode < 500);
            res.resume();
        });
        req.on('timeout', () => {
            req.destroy();
            resolve(false);
        });
        req.on('error', () => resolve(false));
    });
}

initializePersistence().catch((e) => console.warn('initializePersistence failed', e && e.message));
server.on('error', async (err) => {
    if (err && err.code === 'EADDRINUSE') {
        const alive = await probeExistingServer(PORT);
        if (alive) {
            console.warn(`Port ${PORT} is already in use, but Craft Seal is reachable at http://127.0.0.1:${PORT}.`);
            process.exit(0);
            return;
        }
        console.error(`Port ${PORT} is already in use by another process. Stop it or set PORT in .env.`);
        process.exit(1);
        return;
    }
    console.error('Server failed to start:', err && err.message ? err.message : err);
    process.exit(1);
});
server.listen(PORT, () => console.log(`Craft Seal server running at http://127.0.0.1:${PORT}`));
