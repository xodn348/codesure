import { describe, expect, it } from 'bun:test';
import { scanCode } from '../../src/tools/scan-code.js';

interface BenignSample {
  name: string;
  code: string;
}

const benignExpressStyleSamples: BenignSample[] = [
  {
    name: 'express-json-route',
    code: `
      import express from 'express';
      const app = express();
      app.use(express.json());

      app.post('/users', async (req, res) => {
        const id = Number(req.body.id ?? 0);
        const user = await db.users.findUnique({ where: { id } });
        res.json({ ok: true, user });
      });
    `,
  },
  {
    name: 'express-parameterized-query',
    code: `
      app.get('/orders/:id', async (req, res) => {
        const { id } = req.params;
        const order = await pool.query(
          'SELECT * FROM orders WHERE id = $1',
          [id],
        );
        res.json(order.rows[0] ?? null);
      });
    `,
  },
  {
    name: 'express-safe-child-process',
    code: `
      import { spawn } from 'node:child_process';

      app.post('/list', (req, res) => {
        const child = spawn('ls', ['-la'], { shell: false });
        let output = '';
        child.stdout.on('data', (chunk) => {
          output += chunk.toString();
        });
        child.on('close', () => res.type('text/plain').send(output));
      });
    `,
  },
  {
    name: 'express-template-render',
    code: `
      app.get('/welcome', (req, res) => {
        const username = String(req.query.name ?? 'guest');
        res.render('welcome', { username });
      });
    `,
  },
  {
    name: 'express-fetch-upstream',
    code: `
      app.get('/health', async (_req, res) => {
        const upstream = await fetch('https://api.example.com/health');
        const json = await upstream.json();
        res.json({ service: 'api', upstream: json.status ?? 'unknown' });
      });
    `,
  },
];

describe('real-world false positive check', () => {
  it('keeps benign express-style snippets under FP budget', async () => {
    let totalFindings = 0;

    for (const sample of benignExpressStyleSamples) {
      const result = await scanCode(sample.code, 'javascript', `${sample.name}.js`);
      totalFindings += result.findings.length;
      expect(result.findings.length).toBeLessThanOrEqual(5);
    }

    expect(totalFindings).toBeLessThanOrEqual(15);
  });
});
