const request = require('supertest');
const app = require('../server');

describe('Password Manager server', () => {
  it('returns healthy status on /health', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('never leaks secrets from the health endpoint', async () => {
    const res = await request(app).get('/health');
    const text = JSON.stringify(res.body).toLowerCase();
    expect(text).not.toMatch(/password|secret|key|vault/);
  });

  it('serves the frontend entry point', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toBe(200);
    expect(res.text).toMatch(/Password Manager/);
  });

  it('serves the client-side crypto module (no server-side crypto secrets)', async () => {
    const res = await request(app).get('/crypto.js');
    expect(res.statusCode).toBe(200);
    expect(res.text).toMatch(/AES-GCM/);
  });

  it('sets baseline security headers', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toBeDefined();
  });
});
