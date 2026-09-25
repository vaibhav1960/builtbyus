const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.xml': 'application/xml; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

// Security headers applied to all responses
function setSecurityHeaders(res, isHtml = false) {
  // Force HTTPS & Transport Security
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  // Security hygiene headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  if (isHtml) {
    res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  } else {
    // 1-day client cache for static media & fonts with 7-day stale revalidation
    res.setHeader('Cache-Control', 'public, max-age=86400, stale-while-revalidate=604800');
  }
}

// Serve custom 404 page
function serve404(res) {
  const notFoundPath = path.join(PUBLIC_DIR, '404.html');
  fs.readFile(notFoundPath, (err, content) => {
    setSecurityHeaders(res, true);
    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    if (err) {
      res.end('<h1>404 — Page Not Found</h1><p><a href="/">Return to Home</a></p>');
    } else {
      res.end(content);
    }
  });
}

const server = http.createServer((req, res) => {
  // 1. Force HTTPS check (handles reverse proxies such as Cloudflare, Netlify, Render, AWS, Heroku)
  const forwardedProto = req.headers['x-forwarded-proto'];
  if (forwardedProto && forwardedProto !== 'https') {
    const host = req.headers.host || 'builtbyus.dev';
    res.writeHead(301, {
      Location: `https://${host}${req.url}`
    });
    return res.end();
  }

  // Parse path & sanitize
  let reqUrl = req.url.split('?')[0];
  if (reqUrl === '/') reqUrl = '/index.html';

  const safeSuffix = path.normalize(reqUrl).replace(/^(\.\.[\/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, safeSuffix);

  // Check file status
  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Check if it matches a root .html route (e.g. /privacy or /terms)
      const tryHtmlPath = `${filePath}.html`;
      fs.stat(tryHtmlPath, (htmlErr, htmlStats) => {
        if (!htmlErr && htmlStats.isFile()) {
          fs.readFile(tryHtmlPath, (readErr, content) => {
            if (readErr) return serve404(res);
            setSecurityHeaders(res, true);
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(content);
          });
          return;
        }

        // Return dedicated 404 page
        return serve404(res);
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    const isHtml = ext === '.html';

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        setSecurityHeaders(res, false);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('500 Internal Server Error');
        return;
      }

      setSecurityHeaders(res, isHtml);
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    });
  });
});

server.listen(PORT, () => {
  console.log(`\n========================================`);
  console.log(`🚀 Builtbyus is running locally!`);
  console.log(`👉 Local:   http://localhost:${PORT}`);
  console.log(`🔒 Security headers & HTTPS ready`);
  console.log(`📄 404 fallback configured`);
  console.log(`========================================\n`);
});
