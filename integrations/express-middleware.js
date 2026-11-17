/**
 * Middleware Express para o Moracle - envia cada requisicao para o
 * servidor Moracle rodando localmente, sem bloquear a resposta normal
 * da aplicacao (fire-and-forget, com timeout curto).
 *
 * Uso:
 *   const moracle = require('./moracle-middleware');
 *   app.use(moracle({ url: 'http://localhost:7331', apiKey: '...' }));
 */
const http = require('http');

function moracleMiddleware(opcoes) {
  const url = new URL((opcoes.url || 'http://localhost:7331') + '/ingest');
  const apiKey = opcoes.apiKey;
  const timeoutMs = opcoes.timeoutMs || 500;

  if (!apiKey) {
    console.warn('[moracle] apiKey nao configurada — middleware desativado');
    return (req, res, next) => next();
  }

  return function (req, res, next) {
    const payload = JSON.stringify({
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
      method: req.method,
      path: req.originalUrl,
      user_agent: req.headers['user-agent'] || '-',
      status_code: 0,
    });

    const reqOpts = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Authorization': `Bearer ${apiKey}`,
      },
      timeout: timeoutMs,
    };

    const moracleReq = http.request(reqOpts, () => {});
    moracleReq.on('error', () => {});   // nunca derruba a app se o Moracle estiver offline
    moracleReq.on('timeout', () => moracleReq.destroy());
    moracleReq.write(payload);
    moracleReq.end();

    next();  // segue o fluxo normal da aplicacao imediatamente, sem esperar o Moracle
  };
}

module.exports = moracleMiddleware;
