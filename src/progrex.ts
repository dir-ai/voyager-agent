import { LlmBrain, type ChatMessage, type Complete, type LlmBrainOptions } from './llm-brain.js'

/**
 * Wiring Progrex 5 (Progrex Faber g5's coder-nav model) in as Voyager's brain. It
 * plans, ROUTES among the family's capabilities (via LlmBrain.pickNextAsync), and
 * synthesizes — while the senses, the mission machinery and the hands stay put and
 * independently upgradable. Nothing built so far is thrown away: this is one more
 * `Complete` adapter behind the same model-independent seam.
 */
export interface ProgrexBrainOptions {
  /** Base URL of the Progrex 5 OpenAI-compatible server, e.g.
   *  `http://127.0.0.1:11434/v1`. A trailing slash is fine. */
  baseUrl: string
  /** Model id to request. Defaults to Progrex Faber g5's coder-nav model. */
  model?: string
  /** Optional bearer token (a local Progrex server usually needs none). */
  apiKey?: string
  /** Sampling temperature — kept low so planning/routing/synthesis are stable. */
  temperature?: number
  /** Per-call timeout in ms (default 30s). A slow model degrades to the
   *  deterministic brain for that step rather than hanging the mission. */
  timeoutMs?: number
  /** Inject a custom fetch (tests, or a non-HTTP transport). Defaults to the
   *  global `fetch`. */
  fetchImpl?: typeof fetch
  /** Notified when a model step can't be used and the rule-based brain steps in. */
  onFallback?: LlmBrainOptions['onFallback']
}

/** Progrex Faber g5's local coder-navigator model id. */
export const PROGREX_DEFAULT_MODEL = 'progrex:coder-14b-g5-nav'

/**
 * A ready-made `Complete` for Progrex 5 over the OpenAI-compatible
 * `/chat/completions` shape — the de-facto standard local model servers speak
 * (the Progrex nav server, llama.cpp, vLLM, Ollama's `/v1`, LM Studio). If Progrex
 * ever serves a different shape, build your own `Complete`; this is just the
 * batteries-included one. Returns the assistant text; throws on any transport or
 * shape failure so `LlmBrain` falls back safely.
 */
export function progrexComplete(opts: ProgrexBrainOptions): Complete {
  const base = opts.baseUrl.replace(/\/+$/, '')
  const model = opts.model ?? PROGREX_DEFAULT_MODEL
  const doFetch = opts.fetchImpl ?? fetch
  const timeoutMs = opts.timeoutMs ?? 30_000
  return async (messages: ChatMessage[]): Promise<string> => {
    const ac = new AbortController()
    const timer = setTimeout(() => ac.abort(), timeoutMs)
    try {
      const res = await doFetch(`${base}/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(opts.apiKey ? { authorization: `Bearer ${opts.apiKey}` } : {}),
        },
        body: JSON.stringify({ model, temperature: opts.temperature ?? 0.1, messages, stream: false }),
        signal: ac.signal,
      })
      if (!res.ok) throw new Error(`progrex responded ${res.status}`)
      const data = (await res.json()) as { choices?: Array<{ message?: { content?: unknown } }> }
      const content = data.choices?.[0]?.message?.content
      if (typeof content !== 'string' || !content.trim()) throw new Error('progrex returned no message content')
      return content
    } finally {
      clearTimeout(timer)
    }
  }
}

/**
 * Progrex 5 AS Voyager's brain. Drop it into `runMission(intent, { brain }, now)`
 * and Progrex acquires the whole family in one mission: it decomposes intent,
 * routes among the real senses + hands by their LEARNED capability utility, and
 * fuses the conclusion — every step fail-safe to the deterministic brain.
 *
 *   const brain = new ProgrexBrain({ baseUrl: 'http://127.0.0.1:11434/v1' })
 *   const { mission } = await runMission('audit and propose fixes', { repoPath: '.', host, authorized: true, brain }, Date.now())
 */
export class ProgrexBrain extends LlmBrain {
  constructor(opts: ProgrexBrainOptions) {
    super({ complete: progrexComplete(opts), onFallback: opts.onFallback })
  }
}
