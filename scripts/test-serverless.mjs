import http from 'node:http';
import handler from '../api/index.js';

// Simulates Vercel's rewrite: every /api/* request arrives as
// /api/index?__ipath=<original>
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const original = url.pathname;
  if (original.startsWith('/api/')) {
    const rest = original.slice('/api/'.length);
    const injected = rest === 'index' ? url.searchParams.get('__ipath') || '' : rest;
    const params = new URLSearchParams(url.search);
    params.delete('__ipath');
    params.set('__ipath', injected);
    req.url = `/api/index?${params.toString()}`;
  }
  handler(req, res);
});

server.listen(3100, '127.0.0.1', () => console.log('test server on 3100'));
