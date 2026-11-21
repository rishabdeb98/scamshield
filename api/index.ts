import crypto from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import { runMessageAnalysis, runUrlAnalysis } from '../server/detection/engine.ts';
import { DEMO_SAMPLES } from '../server/detection/samples.ts';
import type {
  AwarenessProgress,
  MessageChannel,
  ScamLibraryCategory,
} from '../src/types/scamshield.ts';

const VALID_CHANNELS = new Set<MessageChannel>(['auto', 'sms', 'whatsapp', 'email', 'social']);
const VALID_LIBRARY_CATEGORIES = new Set<ScamLibraryCategory>([
  'Banking',
  'UPI',
  'Government',
  'Delivery',
  'Job',
  'Financial',
  'Phishing',
]);
const MAX_MESSAGE_LENGTH = 5000;
const MAX_URL_LENGTH = 2048;

const EMPTY_AWARENESS: AwarenessProgress = {
  exploredExampleIds: [],
  exploredCategories: [],
  quizAttempts: 0,
  bestQuizScore: null,
  lastQuizScore: null,
};

function verifyCsrfAndOrigin(req: Request, res: Response, next: NextFunction): void {
  const xRequestedWith = req.headers['x-requested-with'];
  const origin = req.headers.origin;
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '') as string;

  if (origin && host) {
    try {
      const originHost = new URL(origin).host;
      if (originHost !== host) {
        res.status(403).json({ error: 'Cross-origin request rejected.' });
        return;
      }
    } catch {
      res.status(403).json({ error: 'Invalid Origin header.' });
      return;
    }
  }

  if (xRequestedWith !== 'ScamShield') {
    res.status(403).json({ error: 'Missing required anti-CSRF request header.' });
    return;
  }

  next();
}

export function createStatelessApiApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    next();
  });

  app.use(express.json({ limit: '32kb' }));

  app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (err instanceof SyntaxError && 'status' in err) {
      res.status(400).json({ error: 'Invalid JSON request body.' });
      return;
    }
    next(err);
  });

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', mode: 'stateless' });
  });

  app.get('/api/samples', (_req, res) => {
    res.json({ samples: DEMO_SAMPLES, mode: 'stateless' });
  });

  app.post('/api/analyze/message', verifyCsrfAndOrigin, (req, res) => {
    const body = req.body as Record<string, unknown> | undefined;
    if (!body || typeof body.message !== 'string') {
      res.status(400).json({ error: 'Please provide a valid text message to analyse.' });
      return;
    }

    const trimmed = body.message.trim();
    if (!trimmed) {
      res.status(400).json({ error: 'Message cannot be empty.' });
      return;
    }

    if (trimmed.length > MAX_MESSAGE_LENGTH) {
      res.status(400).json({
        error: `Message exceeds the maximum allowed length of ${MAX_MESSAGE_LENGTH} characters.`,
      });
      return;
    }

    const rawChannel = typeof body.channel === 'string' ? body.channel : 'auto';
    const channel: MessageChannel = VALID_CHANNELS.has(rawChannel as MessageChannel)
      ? (rawChannel as MessageChannel)
      : 'auto';

    const saveToHistory = body.saveToHistory !== false;
    const result = runMessageAnalysis({ text: trimmed, channel, saveToHistory });
    if (saveToHistory) {
      result.id = crypto.randomUUID();
    }

    res.json({ result, mode: 'stateless' });
  });

  app.post('/api/analyze/url', verifyCsrfAndOrigin, (req, res) => {
    const body = req.body as Record<string, unknown> | undefined;
    if (!body || typeof body.url !== 'string') {
      res.status(400).json({ error: 'Please provide a URL string to check.' });
      return;
    }

    const trimmed = body.url.trim();
    if (!trimmed) {
      res.status(400).json({ error: 'URL input cannot be empty.' });
      return;
    }

    if (trimmed.length > MAX_URL_LENGTH) {
      res.status(400).json({
        error: `URL exceeds the maximum allowed length of ${MAX_URL_LENGTH} characters.`,
      });
      return;
    }

    const saveToHistory = body.saveToHistory !== false;
    const result = runUrlAnalysis({ url: trimmed, saveToHistory });
    if (saveToHistory) {
      result.id = crypto.randomUUID();
    }

    res.json({ result, mode: 'stateless' });
  });

  app.get('/api/history', (_req, res) => {
    res.json({ items: [], mode: 'stateless' });
  });

  app.delete('/api/history/:id', verifyCsrfAndOrigin, (req, res) => {
    const entryId = req.params.id;
    if (!entryId || entryId.length > 64 || !/^[a-z0-9-]+$/i.test(entryId)) {
      res.status(400).json({ error: 'Invalid history entry ID.' });
      return;
    }
    res.json({ deleted: true, mode: 'stateless' });
  });

  app.delete('/api/history', verifyCsrfAndOrigin, (_req, res) => {
    res.json({ cleared: true, deletedCount: 0, mode: 'stateless' });
  });

  app.get('/api/awareness', (_req, res) => {
    res.json({ progress: EMPTY_AWARENESS, mode: 'stateless' });
  });

  app.post('/api/awareness/example', verifyCsrfAndOrigin, (req, res) => {
    const body = req.body as Record<string, unknown> | undefined;
    const exampleId = typeof body?.exampleId === 'string' ? body.exampleId.trim() : '';
    const category = typeof body?.category === 'string' ? body.category.trim() : '';

    if (!exampleId || exampleId.length > 64 || !/^[a-z0-9-]+$/i.test(exampleId)) {
      res.status(400).json({ error: 'Invalid scam library example ID.' });
      return;
    }
    if (!VALID_LIBRARY_CATEGORIES.has(category as ScamLibraryCategory)) {
      res.status(400).json({ error: 'Invalid scam library category.' });
      return;
    }

    res.json({ progress: EMPTY_AWARENESS, mode: 'stateless' });
  });

  app.post('/api/awareness/quiz', verifyCsrfAndOrigin, (req, res) => {
    const body = req.body as Record<string, unknown> | undefined;
    const score = typeof body?.score === 'number' ? body.score : Number.NaN;
    if (!Number.isFinite(score) || score < 0 || score > 100) {
      res.status(400).json({ error: 'Quiz score must be a number between 0 and 100.' });
      return;
    }

    res.json({ progress: EMPTY_AWARENESS, mode: 'stateless' });
  });

  app.use('/api/*', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found.' });
  });

  return app;
}

const app = createStatelessApiApp();
export default app;
