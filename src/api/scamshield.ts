import type {
  AnalysisResult,
  AwarenessProgress,
  HistoryItem,
  MessageChannel,
  SampleMessage,
  ScamLibraryCategory,
} from '../types/scamshield';
import {
  clearBrowserHistory,
  deleteBrowserHistoryItem,
  readBrowserAwareness,
  readBrowserHistory,
  recordBrowserExampleExplored,
  recordBrowserQuizAttempt,
  saveBrowserHistoryResult,
} from '../utils/browserStorage';

// Held strictly in JS memory (never localStorage/sessionStorage) so session
// history stays consistent even when an embedded iframe blocks third-party cookies.
let inMemorySessionToken: string | null = null;
let isStatelessBackend = false;

function buildHeaders(includeJsonContentType = false): Record<string, string> {
  const headers: Record<string, string> = {
    'X-Requested-With': 'ScamShield',
  };
  if (includeJsonContentType) {
    headers['Content-Type'] = 'application/json';
  }
  if (inMemorySessionToken) {
    headers.Authorization = `Bearer ${inMemorySessionToken}`;
  }
  return headers;
}

async function parseJsonResponse<T>(
  res: Response,
): Promise<T & { mode?: string; sessionToken?: string }> {
  const raw = await res.text();
  let data: (T & { error?: string; sessionToken?: string; mode?: string }) | null = null;
  if (raw) {
    try {
      data = JSON.parse(raw) as T & { error?: string; sessionToken?: string; mode?: string };
    } catch {
      data = null;
    }
  }

  if (!res.ok) {
    throw new Error(data?.error || `Request failed (${res.status}). Please try again.`);
  }
  if (!data) {
    throw new Error('Unexpected empty response from server.');
  }
  if (typeof data.sessionToken === 'string' && data.sessionToken.length > 0) {
    inMemorySessionToken = data.sessionToken;
  }
  if (data.mode === 'stateless') {
    isStatelessBackend = true;
  }
  return data;
}

export async function fetchSamples(): Promise<SampleMessage[]> {
  const res = await fetch('/api/samples', { credentials: 'include' });
  const data = await parseJsonResponse<{ samples: SampleMessage[] }>(res);
  return data.samples;
}

export async function analyzeMessageApi(params: {
  message: string;
  channel: MessageChannel;
  saveToHistory: boolean;
}): Promise<AnalysisResult> {
  const res = await fetch('/api/analyze/message', {
    method: 'POST',
    headers: buildHeaders(true),
    credentials: 'include',
    body: JSON.stringify(params),
  });
  const data = await parseJsonResponse<{ result: AnalysisResult }>(res);
  if ((data.mode === 'stateless' || isStatelessBackend) && params.saveToHistory !== false) {
    const saved = saveBrowserHistoryResult(data.result);
    return saved.result;
  }
  return data.result;
}

export async function analyzeUrlApi(params: {
  url: string;
  saveToHistory: boolean;
}): Promise<AnalysisResult> {
  const res = await fetch('/api/analyze/url', {
    method: 'POST',
    headers: buildHeaders(true),
    credentials: 'include',
    body: JSON.stringify(params),
  });
  const data = await parseJsonResponse<{ result: AnalysisResult }>(res);
  if ((data.mode === 'stateless' || isStatelessBackend) && params.saveToHistory !== false) {
    const saved = saveBrowserHistoryResult(data.result);
    return saved.result;
  }
  return data.result;
}

export async function fetchHistoryApi(): Promise<HistoryItem[]> {
  const res = await fetch('/api/history', {
    headers: buildHeaders(false),
    credentials: 'include',
  });
  const data = await parseJsonResponse<{ items: HistoryItem[] }>(res);
  if (data.mode === 'stateless' || isStatelessBackend) {
    return readBrowserHistory();
  }
  return data.items;
}

export async function deleteHistoryItemApi(id: string): Promise<void> {
  const res = await fetch(`/api/history/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: buildHeaders(false),
    credentials: 'include',
  });
  const data = await parseJsonResponse<{ deleted: boolean }>(res);
  if (data.mode === 'stateless' || isStatelessBackend) {
    deleteBrowserHistoryItem(id);
  }
}

export async function clearHistoryApi(): Promise<void> {
  const res = await fetch('/api/history', {
    method: 'DELETE',
    headers: buildHeaders(false),
    credentials: 'include',
  });
  const data = await parseJsonResponse<{ cleared: boolean }>(res);
  if (data.mode === 'stateless' || isStatelessBackend) {
    clearBrowserHistory();
  }
}

export async function fetchAwarenessApi(): Promise<AwarenessProgress> {
  const res = await fetch('/api/awareness', {
    headers: buildHeaders(false),
    credentials: 'include',
  });
  const data = await parseJsonResponse<{ progress: AwarenessProgress }>(res);
  if (data.mode === 'stateless' || isStatelessBackend) {
    return readBrowserAwareness();
  }
  return data.progress;
}

export async function recordExampleExploredApi(
  exampleId: string,
  category: ScamLibraryCategory,
): Promise<AwarenessProgress> {
  const res = await fetch('/api/awareness/example', {
    method: 'POST',
    headers: buildHeaders(true),
    credentials: 'include',
    body: JSON.stringify({ exampleId, category }),
  });
  const data = await parseJsonResponse<{ progress: AwarenessProgress }>(res);
  if (data.mode === 'stateless' || isStatelessBackend) {
    return recordBrowserExampleExplored(exampleId, category);
  }
  return data.progress;
}

export async function recordQuizAttemptApi(score: number): Promise<AwarenessProgress> {
  const res = await fetch('/api/awareness/quiz', {
    method: 'POST',
    headers: buildHeaders(true),
    credentials: 'include',
    body: JSON.stringify({ score }),
  });
  const data = await parseJsonResponse<{ progress: AwarenessProgress }>(res);
  if (data.mode === 'stateless' || isStatelessBackend) {
    return recordBrowserQuizAttempt(score);
  }
  return data.progress;
}
