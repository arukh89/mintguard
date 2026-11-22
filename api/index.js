// Vercel serverless entry. All routes live in ../lib/handler.js;
// this file only adapts the platform request/response shape.
'use strict';

const { handle } = require('../lib/handler');

module.exports = async (req, res) => {
  const path = req.url || '/';
  let body = req.body;
  if (typeof body === 'string' && body) {
    try { body = JSON.parse(body); } catch { body = undefined; }
  }
  const out = await handle(req.method, path, body, undefined, req.headers);
  res.status(out.status);
  for (const [k, v] of Object.entries(out.headers || {})) res.setHeader(k, v);
  res.send(out.body);
};
