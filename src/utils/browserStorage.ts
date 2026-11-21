import type {
  AnalysisResult,
  AwarenessProgress,
  HistoryItem,
  ScamLibraryCategory,
} from '../types/scamshield';

export const BROWSER_HISTORY_KEY = 'scamshield_history_v1';
export const BROWSER_AWARENESS_KEY = 'scamshield_awareness_v1';
const MAX_BROWSER_HISTORY = 250;

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

function getDefaultStorage(): StorageLike | null {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage;
    }
  } catch {
    return null;
  }
  return null;
}

function isValidHistoryItem(item: unknown): item is HistoryItem {
  if (!item || typeof item !== 'object') return false;
  const candidate = item as Partial<HistoryItem>;
  return (
    typeof candidate.id === 'string' &&
    candidate.id.length > 0 &&
    (candidate.mode === 'message' || candidate.mode === 'url') &&
    typeof candidate.redactedPreview === 'string' &&
    typeof candidate.score === 'number' &&
    typeof candidate.classification === 'string' &&
    typeof candidate.summary === 'string' &&
    typeof candidate.createdAt === 'string' &&
    Boolean(candidate.result && typeof candidate.result === 'object')
  );
}

export function readBrowserHistory(storage: StorageLike | null = getDefaultStorage()): HistoryItem[] {
  if (!storage) return [];
  try {
    const raw = storage.getItem(BROWSER_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isValidHistoryItem).slice(0, MAX_BROWSER_HISTORY);
  } catch {
    return [];
  }
}

export function saveBrowserHistoryResult(
  result: AnalysisResult,
  storage: StorageLike | null = getDefaultStorage(),
): HistoryItem {
  const id =
    result.id && result.id.length > 0
      ? result.id
      : typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  const normalizedResult: AnalysisResult = {
    ...result,
    id,
  };

  const entry: HistoryItem = {
    id,
    mode: normalizedResult.mode,
    channel: normalizedResult.channel ?? 'auto',
    redactedPreview: normalizedResult.redactedPreview,
    score: normalizedResult.score,
    classification: normalizedResult.classification,
    summary: normalizedResult.summary,
    indicatorCount: normalizedResult.indicators.length,
    result: normalizedResult,
    createdAt: normalizedResult.analyzedAt,
  };

  if (storage) {
    try {
      const existing = readBrowserHistory(storage).filter((item) => item.id !== id);
      const next = [entry, ...existing].slice(0, MAX_BROWSER_HISTORY);
      storage.setItem(BROWSER_HISTORY_KEY, JSON.stringify(next));
    } catch {
      // Ignore quota/private-mode storage errors
    }
  }

  return entry;
}

export function deleteBrowserHistoryItem(
  id: string,
  storage: StorageLike | null = getDefaultStorage(),
): void {
  if (!storage) return;
  try {
    const next = readBrowserHistory(storage).filter((item) => item.id !== id);
    storage.setItem(BROWSER_HISTORY_KEY, JSON.stringify(next));
  } catch {
    // Ignore storage errors
  }
}

export function clearBrowserHistory(storage: StorageLike | null = getDefaultStorage()): void {
  if (!storage) return;
  try {
    storage.removeItem(BROWSER_HISTORY_KEY);
  } catch {
    // Ignore storage errors
  }
}

const EMPTY_AWARENESS: AwarenessProgress = {
  exploredExampleIds: [],
  exploredCategories: [],
  quizAttempts: 0,
  bestQuizScore: null,
  lastQuizScore: null,
};

export function readBrowserAwareness(
  storage: StorageLike | null = getDefaultStorage(),
): AwarenessProgress {
  if (!storage) return { ...EMPTY_AWARENESS };
  try {
    const raw = storage.getItem(BROWSER_AWARENESS_KEY);
    if (!raw) return { ...EMPTY_AWARENESS };
    const parsed = JSON.parse(raw) as Partial<AwarenessProgress> | null;
    if (!parsed || typeof parsed !== 'object') return { ...EMPTY_AWARENESS };
    return {
      exploredExampleIds: Array.isArray(parsed.exploredExampleIds)
        ? parsed.exploredExampleIds.filter((id): id is string => typeof id === 'string')
        : [],
      exploredCategories: Array.isArray(parsed.exploredCategories)
        ? parsed.exploredCategories.filter((cat): cat is ScamLibraryCategory => typeof cat === 'string')
        : [],
      quizAttempts:
        typeof parsed.quizAttempts === 'number' && parsed.quizAttempts >= 0
          ? Math.floor(parsed.quizAttempts)
          : 0,
      bestQuizScore:
        typeof parsed.bestQuizScore === 'number' &&
        parsed.bestQuizScore >= 0 &&
        parsed.bestQuizScore <= 100
          ? Math.round(parsed.bestQuizScore)
          : null,
      lastQuizScore:
        typeof parsed.lastQuizScore === 'number' &&
        parsed.lastQuizScore >= 0 &&
        parsed.lastQuizScore <= 100
          ? Math.round(parsed.lastQuizScore)
          : null,
    };
  } catch {
    return { ...EMPTY_AWARENESS };
  }
}

export function recordBrowserExampleExplored(
  exampleId: string,
  category: ScamLibraryCategory,
  storage: StorageLike | null = getDefaultStorage(),
): AwarenessProgress {
  const current = readBrowserAwareness(storage);
  const exploredExampleIds = current.exploredExampleIds.includes(exampleId)
    ? current.exploredExampleIds
    : [...current.exploredExampleIds, exampleId];
  const exploredCategories = current.exploredCategories.includes(category)
    ? current.exploredCategories
    : [...current.exploredCategories, category];

  const next: AwarenessProgress = {
    ...current,
    exploredExampleIds,
    exploredCategories,
  };

  if (storage) {
    try {
      storage.setItem(BROWSER_AWARENESS_KEY, JSON.stringify(next));
    } catch {
      // Ignore storage errors
    }
  }
  return next;
}

export function recordBrowserQuizAttempt(
  rawScore: number,
  storage: StorageLike | null = getDefaultStorage(),
): AwarenessProgress {
  const score = Math.max(0, Math.min(100, Math.round(rawScore)));
  const current = readBrowserAwareness(storage);
  const next: AwarenessProgress = {
    ...current,
    quizAttempts: current.quizAttempts + 1,
    bestQuizScore: current.bestQuizScore === null ? score : Math.max(current.bestQuizScore, score),
    lastQuizScore: score,
  };

  if (storage) {
    try {
      storage.setItem(BROWSER_AWARENESS_KEY, JSON.stringify(next));
    } catch {
      // Ignore storage errors
    }
  }
  return next;
}
