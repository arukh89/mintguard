// Local dev server (Node stdlib only). `node server.js` — listens on PORT or 3000.
'use strict';

const http = require('node:http');
const { handle } = require('./lib/handler');

const PORT = Number(process.env.PORT || 3000);

const server = http.createServer(async (req, res) => {
  try {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', async () => {
      let body;
      if (raw) {
        try { body = JSON.parse(raw); } catch { return send(res, 400, { ok: false, error: 'invalid JSON' }); }
      }
      const out = await handle(req.method, req.url, body);
      send(res, out.status, out.body, out.headers);
    });
  } catch (e) {
    send(res, 500, { ok: false, error: String(e && e.message ? e.message : e) });
  }
});

function send(res, status, body, headers) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...(headers || {}) });
  res.end(payload);
}

server.listen(PORT, () => console.log(`mintguard listening on http://localhost:${PORT}`));
