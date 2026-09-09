import { describe, expect, it, vi } from "vitest";
import {
  createMuseAdapter,
  createMuseAuthCredentialSource,
  extractMuseCredential,
  museAuthFilePath,
  museBaseUrl,
  normalizeMusePayload,
  type MuseCredentialResolution,
  type MuseCredentialSource,
} from "../../src/providers/muse.js";
import type { ProviderAdapter } from "../../src/types.js";

const NOW = Date.parse("2026-09-08T12:00:00.000Z");
const OPTIONS = { allowKeychainPrompt: false, refreshCredentials: false };
const SYNTHETIC_TOKEN = "synthetic-muse-access-token";
const AUTH_PATH = "/home/user/.config/muse/auth.json";

// Window reset 2026-09-09T09:32:01Z, weekly reset 2026-09-14T00:00:00Z.
const STAMP = {
  api_key: "LLM|synthetic-session-key-never-reported",
  base_url: "https://api.meta.ai",
  has_payment_method: true,
  require_payment: false,
  is_subs_active: true,
  can_subscribe: false,
  show_subs_upsell: true,
  user_full_name: "Synthetic User",
  user_email: "synthetic@example.com",
  payment_method: "Visa-synthetic",
  action_url: null,
  subs_tier_id: "synthetic-tier",
  subs_tier_name: "Muse Code Everyday",
  is_subs_upgrade_available: true,
  subs_usage: {
    window: {
      used_percent: 6,
      window_duration_mins: 300,
      resets_at: 1788946321,
    },
    weekly: {
      used_percent: 7,
      resets_at: 1789344000,
    },
    tier: "synthetic-tier",
  },
};

function credentialSource(
  resolution: MuseCredentialResolution,
): MuseCredentialSource {
  return {
    resolve: () => resolution,
    inspect: () => {
      if (resolution.status === "available")
        return { status: "available", path: resolution.path };
      return resolution;
    },
  };
}

function availableSource(
  overrides: Partial<
    Extract<MuseCredentialResolution, { status: "available" }>
  > = {},
): MuseCredentialSource {
  return credentialSource({
    status: "available",
    accessToken: SYNTHETIC_TOKEN,
    baseUrl: "https://api.meta.ai",
    path: AUTH_PATH,
    ...overrides,
  });
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function testAdapter(
  overrides: Partial<Parameters<typeof createMuseAdapter>[0]> = {},
): ProviderAdapter {
  return createMuseAdapter({
    credentialSource: availableSource(),
    fetch: vi.fn(async () => jsonResponse(STAMP)) as unknown as typeof fetch,
    readCachedProvider: () => undefined,
    deleteCachedProvider: () => undefined,
    now: () => NOW,
    ...overrides,
  });
}

describe("Muse credential source", () => {
  it("resolves the OAuth login and its stored base URL", () => {
    expect(
      extractMuseCredential(
        {
          schema_version: 1,
          providers: {
            meta: {
              access_token: SYNTHETIC_TOKEN,
              api_base_url: "https://api.meta.ai/v1",
              mechanism: "oauth",
            },
          },
        },
        AUTH_PATH,
      ),
    ).toEqual({
      status: "available",
      accessToken: SYNTHETIC_TOKEN,
      baseUrl: "https://api.meta.ai",
      path: AUTH_PATH,
    });
  });

  it("reports missing when no login is stored", () => {
    expect(extractMuseCredential({}, AUTH_PATH)).toEqual({
      status: "missing",
      path: AUTH_PATH,
    });
    expect(
      extractMuseCredential(
        { providers: { meta: { mechanism: "oauth" } } },
        AUTH_PATH,
      ),
    ).toEqual({ status: "missing", path: AUTH_PATH });
  });

  it("rejects a non-OAuth mechanism instead of sending its secret", () => {
    expect(
      extractMuseCredential(
        {
          providers: {
            meta: { mechanism: "api_key", api_key: "raw-key" },
          },
        },
        AUTH_PATH,
      ),
    ).toEqual({
      status: "invalid",
      path: AUTH_PATH,
      error: "unsupported_mechanism",
    });
  });

  it("falls back to the default base URL when the stored one is unexpected", () => {
    expect(museBaseUrl("https://api.meta.ai/v1")).toBe("https://api.meta.ai");
    expect(museBaseUrl("http://evil.example/key")).toBe("https://api.meta.ai");
    expect(museBaseUrl("not a url")).toBe("https://api.meta.ai");
    expect(museBaseUrl(undefined)).toBe("https://api.meta.ai");
  });

  it("honors MUSE_AUTH_PATH then XDG_CONFIG_HOME then the default", () => {
    const originalMuse = process.env.MUSE_AUTH_PATH;
    const originalXdg = process.env.XDG_CONFIG_HOME;
    try {
      process.env.MUSE_AUTH_PATH = "/tmp/custom-auth.json";
      expect(museAuthFilePath()).toBe("/tmp/custom-auth.json");
      delete process.env.MUSE_AUTH_PATH;
      process.env.XDG_CONFIG_HOME = "/tmp/xdg";
      expect(museAuthFilePath()).toBe("/tmp/xdg/muse/auth.json");
      delete process.env.XDG_CONFIG_HOME;
      expect(museAuthFilePath().endsWith(".config/muse/auth.json")).toBe(true);
    } finally {
      if (originalMuse === undefined) delete process.env.MUSE_AUTH_PATH;
      else process.env.MUSE_AUTH_PATH = originalMuse;
      if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME;
      else process.env.XDG_CONFIG_HOME = originalXdg;
    }
  });

  it("inspects the real file without exposing secrets", async () => {
    const adapter = testAdapter({
      credentialSource: credentialSource({
        status: "missing",
        path: AUTH_PATH,
      }),
    });
    await expect(adapter.inspectAuth(OPTIONS)).resolves.toEqual({
      provider: "muse",
      sources: [
        { source: "muse:auth.json", path: AUTH_PATH, status: "missing" },
      ],
    });
  });
});

describe("Muse subscription stamp request", () => {
  it("posts the stored login to the vendor key endpoint and normalizes both windows", async () => {
    const request = vi.fn(async () => jsonResponse(STAMP));
    const adapter = testAdapter({ fetch: request as unknown as typeof fetch });

    const report = await adapter.fetchQuota(OPTIONS);

    expect(request).toHaveBeenCalledTimes(1);
    const [input, init] = request.mock.calls[0] as [unknown, RequestInit];
    const url = new URL(String(input));
    expect({
      protocol: url.protocol,
      hostname: url.hostname,
      pathname: url.pathname,
    }).toEqual({
      protocol: "https:",
      hostname: "api.meta.ai",
      pathname: "/muse-code/key",
    });
    expect(init?.method).toBe("POST");
    expect(new Headers(init?.headers).get("authorization")).toBe(
      `Bearer ${SYNTHETIC_TOKEN}`,
    );
    expect(report).toMatchObject({
      provider: "muse",
      label: "Muse Code",
      source: "api",
      plan: "Muse Code Everyday",
      account: { email: "synthetic@example.com" },
      state: {
        status: "fresh",
        stale: false,
        sourcesTried: ["muse:auth.json"],
      },
      attempts: [{ source: "muse:auth.json", status: "success" }],
    });
    expect(report.state.untrustedWindowIds).toBeUndefined();
    expect(report.windows).toEqual([
      {
        id: "five_hour",
        label: "5h",
        kind: "session",
        percentUsed: 6,
        percentRemaining: 94,
        windowSeconds: 18_000,
        resetsAt: "2026-09-09T09:32:01.000Z",
      },
      {
        id: "weekly",
        label: "week",
        kind: "weekly",
        percentUsed: 7,
        percentRemaining: 93,
        windowSeconds: 604_800,
        resetsAt: "2026-09-14T00:00:00.000Z",
      },
    ]);
  });

  it("never reports the minted session key or payment metadata", async () => {
    const report = await testAdapter().fetchQuota(OPTIONS);

    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain("synthetic-session-key");
    expect(serialized).not.toContain("Visa-synthetic");
    expect(serialized).not.toContain(SYNTHETIC_TOKEN);
  });

  it("posts to the stored base URL instead of the default", async () => {
    const request = vi.fn(async () => jsonResponse(STAMP));
    const adapter = testAdapter({
      credentialSource: availableSource({
        baseUrl: "https://api.example.invalid",
      }),
      fetch: request as unknown as typeof fetch,
    });

    await adapter.fetchQuota(OPTIONS);

    const [input] = request.mock.calls[0] as [unknown];
    expect(String(input)).toBe("https://api.example.invalid/muse-code/key");
  });

  it("reports auth_required when no login is stored", async () => {
    const deleteCachedProvider = vi.fn();
    const adapter = testAdapter({
      credentialSource: credentialSource({
        status: "missing",
        path: AUTH_PATH,
      }),
      fetch: vi.fn(async () => {
        throw new Error("must not call the network without a credential");
      }) as unknown as typeof fetch,
      deleteCachedProvider: deleteCachedProvider as never,
    });

    const report = await adapter.fetchQuota(OPTIONS);

    expect(report).toMatchObject({
      provider: "muse",
      source: "unavailable",
      windows: [],
      state: {
        status: "auth_required",
        stale: false,
        error: "muse_credential_unavailable",
      },
      attempts: [
        {
          source: "muse:auth.json",
          status: "skipped",
          error: "muse_credential_unavailable",
        },
      ],
    });
    expect(deleteCachedProvider).toHaveBeenCalledWith("muse");
  });

  it("rejects the login and retires the cache when the vendor says 401", async () => {
    const deleteCachedProvider = vi.fn();
    const adapter = testAdapter({
      fetch: vi.fn(
        async () =>
          new Response(null, {
            status: 401,
          }),
      ) as unknown as typeof fetch,
      deleteCachedProvider: deleteCachedProvider as never,
    });

    const report = await adapter.fetchQuota(OPTIONS);

    expect(report.state).toMatchObject({
      status: "auth_required",
      stale: false,
      error: "provider_auth_rejected",
    });
    expect(deleteCachedProvider).toHaveBeenCalledWith("muse");
  });

  it("serves a stale snapshot when the vendor rate-limits", async () => {
    const cached = {
      provider: "muse",
      label: "Muse Code",
      source: "api",
      windows: [
        {
          id: "five_hour",
          label: "5h",
          kind: "session",
          percentUsed: 6,
          percentRemaining: 94,
          windowSeconds: 18_000,
          resetsAt: "2026-09-09T09:32:01.000Z",
        },
      ],
      state: {
        status: "fresh",
        stale: false,
        refreshedAt: new Date(NOW).toISOString(),
      },
    } as never;
    const adapter = testAdapter({
      fetch: vi.fn(
        async () =>
          new Response(null, {
            status: 429,
            headers: { "retry-after": "120" },
          }),
      ) as unknown as typeof fetch,
      readCachedProvider: (() => cached) as never,
    });

    const report = await adapter.fetchQuota(OPTIONS);

    expect(report).toMatchObject({
      provider: "muse",
      source: "cache",
      state: {
        status: "stale",
        stale: true,
        error: "provider_rate_limited",
      },
    });
    expect(report.windows).toHaveLength(1);
  });

  it("names an unparseable present meter as untrusted instead of a complete bound set", async () => {
    const adapter = testAdapter({
      fetch: vi.fn(async () =>
        jsonResponse({
          ...STAMP,
          subs_usage: {
            window: { used_percent: "lots" },
            weekly: { used_percent: 7, resets_at: 1789344000 },
          },
        }),
      ) as unknown as typeof fetch,
    });

    const report = await adapter.fetchQuota(OPTIONS);

    expect(report.state).toMatchObject({
      status: "fresh",
      stale: false,
      untrustedWindowIds: ["five_hour"],
    });
    expect(report.windows).toEqual([
      {
        id: "weekly",
        label: "week",
        kind: "weekly",
        percentUsed: 7,
        percentRemaining: 93,
        windowSeconds: 604_800,
        resetsAt: "2026-09-14T00:00:00.000Z",
      },
    ]);
  });

  it("preserves untrusted window ids on a stale snapshot", async () => {
    const cached = {
      provider: "muse",
      label: "Muse Code",
      source: "api",
      windows: [
        {
          id: "weekly",
          label: "week",
          kind: "weekly",
          percentUsed: 7,
          percentRemaining: 93,
          windowSeconds: 604_800,
          resetsAt: "2026-09-14T00:00:00.000Z",
        },
      ],
      state: {
        status: "fresh",
        stale: false,
        refreshedAt: new Date(NOW).toISOString(),
        untrustedWindowIds: ["five_hour"],
      },
    } as never;
    const adapter = testAdapter({
      fetch: vi.fn(
        async () =>
          new Response(null, {
            status: 429,
            headers: { "retry-after": "120" },
          }),
      ) as unknown as typeof fetch,
      readCachedProvider: (() => cached) as never,
    });

    const report = await adapter.fetchQuota(OPTIONS);

    expect(report.state).toMatchObject({
      status: "stale",
      stale: true,
      untrustedWindowIds: ["five_hour"],
    });
    expect(report.windows).toEqual(cached.windows);
  });

  it("fails closed without a cache on a server error", async () => {
    const adapter = testAdapter({
      fetch: vi.fn(
        async () =>
          new Response("bad gateway", {
            status: 502,
          }),
      ) as unknown as typeof fetch,
    });

    const report = await adapter.fetchQuota(OPTIONS);

    expect(report.state).toMatchObject({
      status: "error",
      stale: false,
      error: "provider_unavailable",
    });
    expect(report.windows).toEqual([]);
  });

  it("returns a fresh empty report when the stamp carries no usage", async () => {
    const request = vi.fn(async () => jsonResponse({ is_subs_active: false }));
    const deleteCachedProvider = vi.fn();
    const adapter = testAdapter({
      fetch: request as unknown as typeof fetch,
      deleteCachedProvider: deleteCachedProvider as never,
    });

    const report = await adapter.fetchQuota(OPTIONS);

    expect(request).toHaveBeenCalledTimes(1);
    expect(report.state.status).toBe("fresh");
    expect(report.windows).toEqual([]);
    // A fresh empty report clears the snapshot via the generic cache path.
    expect(deleteCachedProvider).not.toHaveBeenCalled();
  });
});

describe("normalizeMusePayload", () => {
  it("drops unparseable meters instead of inventing numbers", () => {
    expect(
      normalizeMusePayload({
        subs_tier_name: "Muse Code Everyday",
        subs_usage: {
          window: { used_percent: "lots", resets_at: "soon" },
          weekly: { used_percent: 7, resets_at: 1789344000 },
        },
      }),
    ).toEqual({
      windows: [
        {
          id: "weekly",
          label: "week",
          kind: "weekly",
          percentUsed: 7,
          percentRemaining: 93,
          windowSeconds: 604_800,
          resetsAt: "2026-09-14T00:00:00.000Z",
        },
      ],
      plan: "Muse Code Everyday",
      email: undefined,
      diagnostics: [{ code: "window_invalid" }],
    });
    expect(normalizeMusePayload(null)).toEqual({
      windows: [],
      diagnostics: [],
    });
  });

  it("keeps the stored credential source usable for auth inspection", () => {
    const source = createMuseAuthCredentialSource(() => AUTH_PATH);
    expect(source.inspect().path).toBe(AUTH_PATH);
  });
});
