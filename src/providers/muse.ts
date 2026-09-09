// Muse Code subscription usage, read through the vendor CLI's own
// subscription-status endpoint.
//
// Empirical behavior (Meta Muse Code 1.0.3, observed against the vendor's own
// binary and service, never vendored):
// - Credentials live at `$MUSE_AUTH_PATH`, else `$XDG_CONFIG_HOME/muse/auth.json`,
//   else `~/.config/muse/auth.json`, under `providers.meta` with `mechanism:
//   "oauth"`. The `access_token` there is the bearer the CLI itself mints with.
// - `POST {api_base_url}/muse-code/key` with `Authorization: Bearer
//   <access_token>` returns the startup subscription stamp the CLI's own
//   `/usage` surface renders: `subs_tier_name`, and `subs_usage.window`
//   (rolling 5h: `used_percent`, `window_duration_mins`, `resets_at` epoch
//   seconds) plus `subs_usage.weekly` (`used_percent`, `resets_at`).
// - `GET` on that path is 405; a raw Model API key (`META_API_KEY`, or the
//   stored `api_key`) is 401 there: those keys carry no subscription stamp, so
//   they are deliberately not a credential source here (mirroring Codex, which
//   never treats `OPENAI_API_KEY` as quota auth).
//
// Read-only posture: this call performs no model request and spends no quota.
// The response also carries an ephemeral session key (`api_key`) plus
// `payment_method`/`action_url`; those are dropped immediately and never
// logged, cached, or rendered. Nothing is ever written back to the store, and
// there is no refresh token to exchange, so `refreshCredentials` is ignored
// and the provider stays read-only with no delegated-refresh delegate.

import { homedir } from "node:os";
import { join } from "node:path";
import {
  deleteCachedProvider as deleteCachedProviderFromDisk,
  readCachedProvider as readCachedProviderFromDisk,
} from "../cache.js";
import { readJsonFileResult, type JsonFileReadResult } from "../lib/fs.js";
import { providerFetch } from "../lib/http.js";
import type {
  AuthProviderReport,
  AuthSourceReport,
  ProviderAdapter,
  ProviderOptions,
  ProviderQuota,
  ProviderStatus,
  QuotaWindow,
  SourceAttempt,
} from "../types.js";
import { VERSION } from "../version.js";

const MUSE_KEY_PATH = "/muse-code/key";
const OPERATION_DEADLINE_MS = 15_000;
const RESPONSE_LIMIT_BYTES = 262_144;
const DEFAULT_BASE_URL = "https://api.meta.ai";
const MUSE_AUTH_SOURCE = "muse:auth.json";
const USER_AGENT = `quota-axi/${VERSION}`;

const FIVE_HOURS_SECONDS = 5 * 60 * 60;
const WEEK_SECONDS = 7 * 24 * 60 * 60;

export type MuseDiagnostic =
  | { code: "window_invalid" }
  | { code: "weekly_invalid" };

export type NormalizedMusePayload = {
  windows: QuotaWindow[];
  plan?: string;
  email?: string;
  diagnostics: MuseDiagnostic[];
};

export type MuseCredentialResolution =
  | {
      status: "available";
      accessToken: string;
      baseUrl: string;
      path: string;
    }
  | { status: "missing"; path: string }
  | { status: "invalid"; path: string; error: string }
  | { status: "error"; path: string; error: string };

export type MuseCredentialInspection =
  | { status: "available"; path: string }
  | { status: "missing"; path: string }
  | { status: "invalid"; path: string; error: string }
  | { status: "error"; path: string; error: string };

export type MuseCredentialSource = {
  resolve(): MuseCredentialResolution;
  inspect(): MuseCredentialInspection;
};

type MuseDependencies = {
  credentialSource: MuseCredentialSource;
  fetch: typeof globalThis.fetch;
  readCachedProvider: typeof readCachedProviderFromDisk;
  deleteCachedProvider: typeof deleteCachedProviderFromDisk;
  now: () => number;
  deadlineMs: number;
};

type MuseFailureOptions = {
  status?: ProviderStatus;
  staleEligible?: boolean;
  definitiveAuth?: boolean;
  retryAfter?: string;
};

type ResponseBodyLifetime = {
  markConsumed(): void;
  cancel(action?: () => Promise<unknown> | undefined): Promise<void>;
};

export function museAuthFilePath(): string {
  const override = stringValue(process.env.MUSE_AUTH_PATH);
  if (override) return override;
  const xdg = stringValue(process.env.XDG_CONFIG_HOME);
  if (xdg) return join(xdg, "muse", "auth.json");
  return join(homedir(), ".config", "muse", "auth.json");
}

/** Base URL the login record points at; anything unexpected falls back. */
export function museBaseUrl(value: unknown): string {
  if (typeof value === "string") {
    const trimmed = value.trim().replace(/\/+$/, "");
    try {
      const url = new URL(trimmed);
      if (url.protocol === "https:" && url.hash === "" && url.search === "") {
        return `${url.protocol}//${url.host}`;
      }
    } catch {
      // Fall through to the default below.
    }
  }
  return DEFAULT_BASE_URL;
}

export function extractMuseCredential(
  value: unknown,
  path: string,
): MuseCredentialResolution {
  const data = objectValue(value);
  const providers = objectValue(data?.providers);
  const meta = objectValue(providers?.meta);
  if (!data || !providers || !meta) return { status: "missing", path };
  const mechanism = stringValue(meta.mechanism);
  if (mechanism !== undefined && mechanism !== "oauth") {
    return {
      status: "invalid",
      path,
      error: "unsupported_mechanism",
    };
  }
  const accessToken = stringValue(meta.access_token);
  if (!accessToken) return { status: "missing", path };
  return {
    status: "available",
    accessToken,
    baseUrl: museBaseUrl(meta.api_base_url),
    path,
  };
}

export function createMuseAuthCredentialSource(
  filePath: () => string = museAuthFilePath,
): MuseCredentialSource {
  function resolve(): MuseCredentialResolution {
    const path = filePath();
    const result: JsonFileReadResult = readJsonFileResult(path);
    if (result.status === "missing") return { status: "missing", path };
    if (result.status === "invalid")
      return result.error === "file_read_error"
        ? { status: "error", path, error: result.error }
        : { status: "invalid", path, error: result.error };
    return extractMuseCredential(result.value, path);
  }
  return {
    resolve,
    inspect(): MuseCredentialInspection {
      const resolution = resolve();
      if (resolution.status === "available")
        return { status: "available", path: resolution.path };
      return resolution;
    },
  };
}

export function createMuseAdapter(
  overrides: Partial<MuseDependencies> = {},
): ProviderAdapter {
  const dependencies: MuseDependencies = {
    credentialSource: createMuseAuthCredentialSource(),
    fetch: providerFetch,
    readCachedProvider: readCachedProviderFromDisk,
    deleteCachedProvider: deleteCachedProviderFromDisk,
    now: Date.now,
    deadlineMs: OPERATION_DEADLINE_MS,
    ...overrides,
  };
  let inFlight: Promise<ProviderQuota> | undefined;

  return {
    id: "muse",
    label: "Muse Code",
    fetchQuota(_options: ProviderOptions): Promise<ProviderQuota> {
      if (inFlight) return inFlight;
      const acquisition = acquireMuseQuota(dependencies).finally(() => {
        if (inFlight === acquisition) inFlight = undefined;
      });
      inFlight = acquisition;
      return acquisition;
    },
    async inspectAuth(_options: ProviderOptions): Promise<AuthProviderReport> {
      const inspection = dependencies.credentialSource.inspect();
      const source: AuthSourceReport = {
        source: MUSE_AUTH_SOURCE,
        path: inspection.path,
        status: inspection.status,
        ...(inspection.status === "invalid" || inspection.status === "error"
          ? { error: inspection.error }
          : {}),
      };
      return { provider: "muse", sources: [source] };
    },
  };
}

export const museAdapter = createMuseAdapter();

async function acquireMuseQuota(
  dependencies: MuseDependencies,
): Promise<ProviderQuota> {
  const controller = new AbortController();
  const deadline = setTimeout(
    () => controller.abort(),
    dependencies.deadlineMs,
  );
  let attempts: SourceAttempt[] = [];

  try {
    const resolution = dependencies.credentialSource.resolve();
    attempts = [{ source: MUSE_AUTH_SOURCE, status: "failed" }];

    if (resolution.status !== "available") {
      const failure = credentialFailureFor(resolution);
      attempts[attempts.length - 1] = {
        source: MUSE_AUTH_SOURCE,
        status: resolution.status === "missing" ? "skipped" : "failed",
        error: failure.code,
      };
      return failureReport(failure, attempts, dependencies);
    }

    const payload = await requestMuseSubscription(
      resolution.baseUrl,
      resolution.accessToken,
      controller.signal,
      dependencies.fetch,
      dependencies.now,
    );
    const normalized = normalizeMusePayload(payload);
    const untrustedWindowIds = normalized.diagnostics.map((diagnostic) =>
      diagnostic.code === "window_invalid" ? "five_hour" : "weekly",
    );
    const refreshedAt = new Date(dependencies.now()).toISOString();
    attempts[attempts.length - 1] = {
      source: MUSE_AUTH_SOURCE,
      status: "success",
    };
    return {
      provider: "muse",
      label: "Muse Code",
      source: "api",
      ...(normalized.plan ? { plan: normalized.plan } : {}),
      ...(normalized.email ? { account: { email: normalized.email } } : {}),
      windows: normalized.windows,
      state: {
        status: "fresh",
        stale: false,
        refreshedAt,
        ...(untrustedWindowIds.length > 0 ? { untrustedWindowIds } : {}),
        sourcesTried: attempts.map(({ source }) => source),
      },
      attempts,
    };
  } catch (error) {
    const failure =
      error instanceof MuseFailure
        ? error
        : new MuseFailure("credential_resolution_failed", {
            staleEligible: true,
          });
    if (attempts.length === 0) {
      attempts = [
        {
          source: MUSE_AUTH_SOURCE,
          status: "failed",
          error: failure.code,
        },
      ];
    } else {
      attempts[attempts.length - 1] = {
        source: attempts[attempts.length - 1].source,
        status: "failed",
        error: failure.code,
      };
    }
    return failureReport(failure, attempts, dependencies);
  } finally {
    clearTimeout(deadline);
  }
}

function credentialFailureFor(
  resolution: Exclude<MuseCredentialResolution, { status: "available" }>,
): MuseFailure {
  if (resolution.status === "missing") {
    return new MuseFailure("muse_credential_unavailable", {
      status: "auth_required",
      definitiveAuth: true,
    });
  }
  if (resolution.status === "error") {
    return new MuseFailure("credential_resolution_failed", {
      staleEligible: true,
    });
  }
  return new MuseFailure("muse_credential_invalid", {
    status: "auth_required",
    definitiveAuth: true,
  });
}

function failureReport(
  failure: MuseFailure,
  attempts: SourceAttempt[],
  dependencies: MuseDependencies,
): ProviderQuota {
  if (failure.definitiveAuth) {
    try {
      dependencies.deleteCachedProvider("muse");
    } catch {
      // The current auth failure is still definitive even if the cache is not writable.
    }
  }

  if (failure.staleEligible) {
    try {
      const cached = dependencies.readCachedProvider("muse");
      const stale = cached
        ? staleMuseReport(
            cached,
            failure.code,
            failure.retryAfter,
            attempts,
            dependencies.now(),
          )
        : undefined;
      if (stale) return stale;
    } catch {
      // Cache I/O cannot replace the bounded current provider failure.
    }
  }

  return {
    provider: "muse",
    label: "Muse Code",
    source: "unavailable",
    windows: [],
    state: {
      status: failure.status,
      stale: false,
      error: failure.code,
      ...(failure.retryAfter ? { retryAfter: failure.retryAfter } : {}),
      sourcesTried: attempts.map(({ source }) => source),
    },
    attempts,
  };
}

function staleMuseReport(
  cached: ProviderQuota,
  error: string,
  retryAfter: string | undefined,
  attempts: SourceAttempt[],
  now: number,
): ProviderQuota | undefined {
  if (
    cached.provider !== "muse" ||
    cached.source !== "api" ||
    cached.state.status !== "fresh" ||
    !cached.state.refreshedAt
  ) {
    return undefined;
  }
  const refreshedAt = Date.parse(cached.state.refreshedAt);
  if (!Number.isFinite(refreshedAt)) return undefined;
  const ageMilliseconds = Math.max(0, now - refreshedAt);
  const windows = cached.windows.filter((window) => {
    if (window.resetsAt) {
      const resetsAt = Date.parse(window.resetsAt);
      if (Number.isFinite(resetsAt)) return resetsAt > now;
    }
    const maxAgeSeconds = maxStaleAgeSeconds(window);
    return maxAgeSeconds > 0 && ageMilliseconds < maxAgeSeconds * 1_000;
  });
  if (windows.length === 0) return undefined;

  return {
    provider: "muse",
    label: "Muse Code",
    source: "cache",
    ...(cached.plan ? { plan: cached.plan } : {}),
    windows,
    state: {
      status: "stale",
      stale: true,
      refreshedAt: cached.state.refreshedAt,
      error,
      ...(retryAfter ? { retryAfter } : {}),
      ...(cached.state.untrustedWindowIds
        ? { untrustedWindowIds: cached.state.untrustedWindowIds }
        : {}),
      sourcesTried: [...attempts.map(({ source }) => source), "cache"],
    },
    attempts,
  };
}

function maxStaleAgeSeconds(window: QuotaWindow): number {
  if (window.windowSeconds !== undefined && window.windowSeconds > 0)
    return window.windowSeconds;
  switch (window.kind) {
    case "session":
      return FIVE_HOURS_SECONDS;
    case "weekly":
      return WEEK_SECONDS;
    default:
      return 0;
  }
}

async function requestMuseSubscription(
  baseUrl: string,
  accessToken: string,
  signal: AbortSignal,
  fetchImplementation: typeof globalThis.fetch,
  now: () => number,
): Promise<unknown> {
  let response: Response;
  try {
    response = await waitForDeadline(
      fetchImplementation(`${baseUrl}${MUSE_KEY_PATH}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
          "Content-Type": "application/json",
          "User-Agent": USER_AGENT,
        },
        body: "{}",
        credentials: "omit",
        redirect: "manual",
        signal,
      }),
      signal,
    );
  } catch (error) {
    if (signal.aborted || isAbortError(error)) {
      throw new MuseFailure("request_timeout", { staleEligible: true });
    }
    throw new MuseFailure(localTransportCode(error), { staleEligible: true });
  }

  const lifetime = createResponseBodyLifetime(response);
  try {
    const receivedAt = now();
    rejectHttpFailure(response, receivedAt);

    let bytes: Uint8Array;
    try {
      bytes = await readBoundedBody(response, signal, lifetime);
      lifetime.markConsumed();
    } catch (error) {
      if (error instanceof MuseFailure) throw error;
      if (signal.aborted || isAbortError(error)) {
        throw new MuseFailure("request_timeout", { staleEligible: true });
      }
      throw new MuseFailure("network_unavailable", { staleEligible: true });
    }

    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new MuseFailure("response_invalid_utf8");
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new MuseFailure("malformed_json");
    }
  } finally {
    await lifetime.cancel();
  }
}

function rejectHttpFailure(response: Response, receivedAt: number): void {
  const status = response.status;
  if (status === 200) return;
  if (status >= 300 && status <= 399) {
    throw new MuseFailure("redirect_rejected");
  }
  if (status === 401 || status === 403) {
    throw new MuseFailure("provider_auth_rejected", {
      status: "auth_required",
      definitiveAuth: true,
    });
  }
  if (status === 408) {
    throw new MuseFailure("provider_timeout", { staleEligible: true });
  }
  if (status === 429) {
    throw new MuseFailure("provider_rate_limited", {
      status: "rate_limited",
      staleEligible: true,
      retryAfter: normalizeRetryAfter(
        response.headers.get("retry-after"),
        receivedAt,
      ),
    });
  }
  if (status >= 500 && status <= 599) {
    throw new MuseFailure("provider_unavailable", { staleEligible: true });
  }
  throw new MuseFailure("provider_request_rejected");
}

async function readBoundedBody(
  response: Response,
  signal: AbortSignal,
  lifetime: ResponseBodyLifetime,
): Promise<Uint8Array> {
  const body = response.body;
  if (!body) {
    const text = await response.text();
    return new TextEncoder().encode(text).slice(0, RESPONSE_LIMIT_BYTES + 1);
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      if (signal.aborted) {
        await lifetime.cancel(() => reader.cancel());
        throw new MuseFailure("request_timeout", { staleEligible: true });
      }
      let result: ReadableStreamReadResult<Uint8Array>;
      try {
        result = await reader.read();
      } catch (error) {
        if (signal.aborted || isAbortError(error)) {
          await lifetime.cancel(() => reader.cancel());
          throw new MuseFailure("request_timeout", { staleEligible: true });
        }
        throw error;
      }
      if (result.done) break;
      if (result.value) {
        total += result.value.byteLength;
        if (total > RESPONSE_LIMIT_BYTES) {
          throw new MuseFailure("response_too_large", {
            staleEligible: true,
          });
        }
        chunks.push(result.value);
      }
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Teardown only; the bytes already read stand.
    }
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

function createResponseBodyLifetime(response: Response): ResponseBodyLifetime {
  let consumed = false;
  let cancellation: Promise<void> | undefined;

  return {
    markConsumed() {
      if (!cancellation) consumed = true;
    },
    async cancel(action = () => response.body?.cancel()) {
      if (consumed) return;
      cancellation ??= Promise.resolve()
        .then(action)
        .then(() => undefined)
        .catch(() => undefined);
      await cancellation;
    },
  };
}

async function waitForDeadline<T>(
  promise: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) throw new MuseFailure("request_timeout");
  return await new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      reject(new MuseFailure("request_timeout"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

/**
 * Normalize the vendor subscription stamp. Only the two documented usage
 * meters become windows; everything else (session key, payment metadata,
 * upsell flags) is dropped here and never reaches the report.
 */
export function normalizeMusePayload(raw: unknown): NormalizedMusePayload {
  const root = objectValue(raw);
  if (!root) return { windows: [], diagnostics: [] };
  const usage = objectValue(root.subs_usage);
  const diagnostics: MuseDiagnostic[] = [];
  const windows: QuotaWindow[] = [];

  const window = normalizeRollingWindow(objectValue(usage?.window));
  if (window) windows.push(window);
  else if (usage && "window" in usage)
    diagnostics.push({ code: "window_invalid" });

  const weekly = normalizeWeeklyWindow(objectValue(usage?.weekly));
  if (weekly) windows.push(weekly);
  else if (usage && "weekly" in usage)
    diagnostics.push({ code: "weekly_invalid" });

  return {
    windows,
    plan: stringValue(root.subs_tier_name),
    email: stringValue(root.user_email),
    diagnostics,
  };
}

function normalizeRollingWindow(
  value: Record<string, unknown> | undefined,
): QuotaWindow | undefined {
  if (!value) return undefined;
  const used = numberValue(value.used_percent);
  if (used === undefined) return undefined;
  const percentUsed = clampPercentage(used);
  const durationMinutes = numberValue(value.window_duration_mins);
  const windowSeconds =
    durationMinutes !== undefined && durationMinutes > 0
      ? Math.round(durationMinutes * 60)
      : FIVE_HOURS_SECONDS;
  const resetsAt = parseResetEpoch(value.resets_at);
  return {
    id: "five_hour",
    label: "5h",
    kind: "session",
    percentUsed,
    percentRemaining: clampPercentage(100 - percentUsed),
    windowSeconds,
    ...(resetsAt ? { resetsAt } : {}),
  };
}

function normalizeWeeklyWindow(
  value: Record<string, unknown> | undefined,
): QuotaWindow | undefined {
  if (!value) return undefined;
  const used = numberValue(value.used_percent);
  if (used === undefined) return undefined;
  const percentUsed = clampPercentage(used);
  const resetsAt = parseResetEpoch(value.resets_at);
  return {
    id: "weekly",
    label: "week",
    kind: "weekly",
    percentUsed,
    percentRemaining: clampPercentage(100 - percentUsed),
    // The vendor declares this meter `weekly` in its fixed subscription
    // schema; like Claude's `seven_day` and the Kimi/Z.AI weekly windows it
    // carries the trusted 604,800-second duration so pace has a cycle basis.
    windowSeconds: WEEK_SECONDS,
    ...(resetsAt ? { resetsAt } : {}),
  };
}

export function normalizeRetryAfter(
  value: string | null,
  receivedAt: number,
): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (trimmed === "") return undefined;
  const seconds = Number(trimmed);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return new Date(receivedAt + seconds * 1_000).toISOString();
  }
  const date = new Date(trimmed);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function parseResetEpoch(value: unknown): string | undefined {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return undefined;
  }
  const milliseconds = value > 100_000_000_000 ? value : value * 1_000;
  const date = new Date(milliseconds);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== ""
    ? value.trim()
    : undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function clampPercentage(value: number): number {
  return Math.min(100, Math.max(0, value));
}

function localTransportCode(_error: unknown): string {
  return "network_unavailable";
}

function isAbortError(error: unknown): boolean {
  return (
    error instanceof DOMException ||
    (error instanceof Error && error.name === "AbortError")
  );
}

export class MuseFailure extends Error {
  readonly code: string;
  readonly status: ProviderStatus;
  readonly staleEligible: boolean;
  readonly definitiveAuth: boolean;
  readonly retryAfter?: string;

  constructor(code: string, options: MuseFailureOptions = {}) {
    super(code);
    this.name = "MuseFailure";
    this.code = code;
    this.status = options.status ?? "error";
    this.staleEligible = options.staleEligible ?? false;
    this.definitiveAuth = options.definitiveAuth ?? false;
    if (options.retryAfter) this.retryAfter = options.retryAfter;
  }
}
