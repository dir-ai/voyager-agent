// Active-verification SEAM — the PUBLIC agent stays READ-ONLY and carries ZERO
// offensive code. It defines an INJECTION seam (mirroring the `brain` seam) so a
// PRIVATE, consent-gated offensive engine can be supplied by the caller to turn a
// suspected web vuln (that the read-only browser sense already DISCOVERED) into a
// DEMONSTRATED, attested fact. With no verifier injected (the default public
// case) the mission behaves EXACTLY as today: it only derives the attack surface
// (read-only) and records a plan-only "verification available" claim.
//
// What is offensive (sending attack-shaped input, the payload catalog, the probe
// engines) lives OUTSIDE this package, behind this interface. What lives here is:
//   1. read-only mapping of a PageBrief's forms/endpoints → target descriptors,
//   2. the fail-closed gate deciding whether to CALL an injected verifier,
//   3. adapting a verifier's confirmed results into `exploit-verified` claims +
//      an honest coverage statement.
import { newClaim, type CognitiveClaim, type Evidence } from '@dir-ai/voyager-contract'
import { stripInjection } from '@dir-ai/voyager'
import type { PageBrief } from '@dir-ai/voyager-browser'
import { USABLE_OBSERVATION_CONFIDENCE } from './constants.js'

/** A web attack-surface target the read-only browser sense discovered — a form
 *  action or a discovered endpoint plus the parameter to test. This is a pure
 *  DESCRIPTOR: it names WHERE to look, never a payload (payloads live in the
 *  injected engine, never here). */
export interface VerifyTarget {
  url: string
  method?: 'GET' | 'POST'
  /** The parameter an injected engine would test. */
  param: string
  /** Parameters held constant across baseline + probe requests. */
  baseParams?: Record<string, string>
  /** A benign baseline value for `param`. */
  baseValue?: string
  /** Where this target came from (form action / discovered endpoint) — provenance. */
  source?: string
}

/** A consent decision the CALLER supplies, bound to a target+probe-set run digest
 *  (anti-replay). The public agent NEVER fabricates the binding — it forwards this
 *  to the injected engine, which is the authority on the gate. Structurally
 *  mirrors the private engine's own consent shape so it passes straight through. */
export interface VerifyConsent {
  approved: boolean
  /** Who/what approved — a human id or an explicit policy id. */
  by: string
  /** Binds the approval to ONE specific target+probe-set (the engine's run digest). */
  actionDigest?: string
  /** For a two-person tier: the second approver. */
  secondBy?: string
  /** Epoch ms after which the approval is stale. */
  expiresAt?: number
  note?: string
}

/** Context handed to an injected verifier. Carries the mission's authorization +
 *  SSRF posture and the caller's consent (a single decision and/or a per-target
 *  resolver). The engine is responsible for binding consent to each target's run
 *  digest and refusing on any mismatch — the agent does not bypass that. */
export interface VerifyContext {
  authorized: boolean
  allowPrivate: boolean
  missionId: string
  now: number
  /** A single consent decision (bound to one target via actionDigest, or a base
   *  identity the resolver refines). */
  consent?: VerifyConsent
  /** Per-target consent resolver — returns the decision granted for THAT target,
   *  bound to its run digest, or null to withhold it. */
  resolveConsent?: (target: VerifyTarget) => VerifyConsent | null | Promise<VerifyConsent | null>
  onLog?: (line: string) => void
}

/** A result from an injected verifier for one probe against one target. Only
 *  `confirmed` is adapted into a DEMONSTRATED `exploit-verified` finding. */
export interface VerifiedFinding {
  target: VerifyTarget
  /** e.g. 'sqli' | 'xss'. */
  vulnKind: string
  /** e.g. 'sqli-boolean' | 'sqli-error' | 'xss-reflect'. */
  probe: string
  verdict: 'confirmed' | 'not-confirmed' | 'inconclusive' | 'withheld' | 'refused' | 'error'
  confidence?: 'strong' | 'moderate' | 'weak'
  detail: string
  /** Reproducible evidence: the differential / the reflected marker / the DB error
   *  signature — label + detail pairs. */
  evidence?: Array<{ label: string; detail: string }>
  /** The engine's attestation receipt — an opaque, verifiable proof id + digest. */
  attestation?: { receipt: string; digest?: string; at?: number; by?: string | null }
  /** The engine that produced this (native probe / wrapped tool id). */
  engine?: string
}

/**
 * The injected offensive engine. UNDEFINED in the public package — supplied only
 * by a private caller (e.g. the workbench's hands-backed adapter). Given the
 * read-only-discovered targets + the mission's authorization/consent, it performs
 * the consent-gated, non-destructive verification and returns the results. The
 * public agent only ever holds a reference to this interface, never an
 * implementation.
 */
export interface ActiveVerifier {
  verify(targets: VerifyTarget[], ctx: VerifyContext): Promise<VerifiedFinding[]>
}

/** The honest coverage statement the signed artifact carries: which vuln classes
 *  were ACTIVELY tested (and confirmed) vs which findings were only OBSERVED
 *  statically — so authenticity never outruns the measured perimeter. */
export interface VerificationCoverage {
  authorized: boolean
  consentProvided: boolean
  verifierPresent: boolean
  /** true only when a verifier actually ran (gated on). */
  ran: boolean
  /** Every target/probe an injected engine actually exercised, with its verdict. */
  activelyTested: Array<{ vulnKind: string; probe: string; target: string; verdict: string }>
  /** The subset that were DEMONSTRATED (confirmed with evidence). */
  confirmed: Array<{ vulnKind: string; target: string; receipt: string | null }>
  /** Static finding kinds observed by the read-only senses that were NOT actively
   *  confirmed — flagged so the report cannot be read as "everything is proven". */
  observedOnly: string[]
  note: string
}

const MAX_TARGETS = 12
const NON_INJECTABLE_TYPES = new Set(['password', 'hidden', 'submit', 'file', 'checkbox', 'radio', 'image', 'button', 'reset'])

/** READ-ONLY: map a single PageBrief's discovered forms + query-bearing endpoints
 *  into target descriptors. Same-origin http(s) only; sensitive/credential fields
 *  are skipped. Sends NOTHING — pure structural derivation. */
export function webProbeTargetsFromBrief(brief: PageBrief): VerifyTarget[] {
  const targets: VerifyTarget[] = []
  const originStr = brief.target.origin ?? brief.target.url ?? undefined
  let originHost: string | null = null
  try {
    if (originStr) originHost = new URL(originStr).origin
  } catch {
    originHost = null
  }
  const sameOrigin = (u: URL): boolean => (originHost ? u.origin === originHost : true)

  for (const form of brief.forms ?? []) {
    let action: URL
    try {
      action = new URL(form.action, originStr)
    } catch {
      continue
    }
    if (!/^https?:$/i.test(action.protocol) || !sameOrigin(action)) continue
    const method = (form.method ?? 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET'
    const injectable = (form.fields ?? []).filter((f) => f.name && !NON_INJECTABLE_TYPES.has((f.type ?? '').toLowerCase()))
    for (const f of injectable.slice(0, 4)) {
      targets.push({ url: `${action.origin}${action.pathname}`, method, param: f.name, source: `form ${method} ${action.pathname}` })
    }
  }

  for (const fnd of brief.findings ?? []) {
    if (!fnd.at) continue
    let u: URL
    try {
      u = new URL(fnd.at, originStr)
    } catch {
      continue
    }
    if (!/^https?:$/i.test(u.protocol) || !sameOrigin(u)) continue
    const keys = [...u.searchParams.keys()]
    if (!keys.length) continue
    const param = keys[0]
    const baseParams: Record<string, string> = {}
    for (const [k, v] of u.searchParams) if (k !== param) baseParams[k] = v
    targets.push({ url: `${u.origin}${u.pathname}`, method: 'GET', param, baseParams: Object.keys(baseParams).length ? baseParams : undefined, source: `endpoint ${fnd.kind}` })
  }
  return targets
}

/** Dedupe + cap targets derived across every observed page. */
export function deriveVerifyTargets(briefs: readonly PageBrief[]): VerifyTarget[] {
  const seen = new Set<string>()
  const out: VerifyTarget[] = []
  for (const b of briefs) {
    for (const t of webProbeTargetsFromBrief(b)) {
      const key = `${t.method ?? 'GET'} ${t.url} ${t.param}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push(t)
      if (out.length >= MAX_TARGETS) return out
    }
  }
  return out
}

/** Distinct static finding kinds observed by the read-only senses. */
function observedFindingKinds(claims: readonly CognitiveClaim[]): string[] {
  const kinds = new Set<string>()
  for (const c of claims) {
    if (c.operation !== 'observe') continue
    for (const e of c.evidence) {
      const m = /^\[(\w+)\]\s*([a-z0-9-]+)\s*:/i.exec(e.what)
      if (m?.[2]) kinds.add(m[2].toLowerCase())
    }
  }
  return [...kinds].sort()
}

function framed(what: string, at: string | undefined, source: string, now: number): Evidence {
  return { what: stripInjection(what).slice(0, 500), at: at ? stripInjection(at).slice(0, 200) : at, framed: true, provenance: { source, capabilityId: 'verify.active', fetchedAt: now } }
}

const CONF: Record<string, number> = { strong: 0.97, moderate: 0.85, weak: 0.7 }

export interface VerificationInput {
  /** The injected offensive engine (undefined in the public package). */
  verify?: ActiveVerifier
  /** A single explicit consent decision. */
  consent?: VerifyConsent
  /** A per-target consent resolver. */
  verifyConsent?: (target: VerifyTarget) => VerifyConsent | null | Promise<VerifyConsent | null>
  /** The mission's offensive-authorization gate. */
  authorized?: boolean
  /** SSRF posture forwarded to the engine (permit the caller's OWN private/loopback). */
  allowPrivate?: boolean
  onLog?: (line: string) => void
}

/**
 * The verification phase. Fail-closed:
 *   RUN the injected verifier ONLY when authorized===true AND consent is provided
 *   AND a verifier is injected. Otherwise record a plan-only "verification
 *   available" claim (never call any engine, send nothing). If NO web attack
 *   surface was discovered, return nothing at all — identical to today.
 * Returns the claims to add to the mission: zero-or-one coverage claim + one
 * `exploit-verified` claim per CONFIRMED finding.
 */
export async function runActiveVerification(
  briefs: readonly PageBrief[],
  input: VerificationInput,
  allClaims: readonly CognitiveClaim[],
  missionId: string,
  now: number,
  goalId?: string,
): Promise<CognitiveClaim[]> {
  const log = input.onLog ?? (() => {})
  const targets = deriveVerifyTargets(briefs)
  if (!targets.length) return [] // no web attack surface → behave EXACTLY as today

  const observedOnly = observedFindingKinds(allClaims)
  const consentProvided = !!(input.consent || input.verifyConsent)
  const verifierPresent = !!input.verify
  const authorized = input.authorized === true
  const gatedOn = authorized && consentProvided && verifierPresent

  if (!gatedOn) {
    const missing: string[] = []
    if (!authorized) missing.push('authorized:true')
    if (!consentProvided) missing.push('explicit consent (consent / verifyConsent)')
    if (!verifierPresent) missing.push('an injected ActiveVerifier (offensive engine — not in the public package)')
    const coverage: VerificationCoverage = {
      authorized, consentProvided, verifierPresent, ran: false,
      activelyTested: [], confirmed: [], observedOnly,
      note: `active verification AVAILABLE for ${targets.length} discovered target(s) but NOT run — requires: ${missing.join(' + ')}. Read-only observation only; nothing was actively tested.`,
    }
    log(`verify: available for ${targets.length} target(s) — withheld (${missing.join(', ')})`)
    return [
      newClaim(
        {
          missionId, goalId, sense: 'web', capability: 'verify.coverage', operation: 'verify',
          verdict: `active verification AVAILABLE — inject a verifier + consent to demonstrate ${targets.length} discovered web target(s); none actively tested`,
          confidence: 0.5,
          unknowns: targets.map((t) => `${t.method ?? 'GET'} ${t.url}?${t.param} — suspected, NOT actively confirmed`),
          verification: { passed: null, method: coverage.note },
          continuationState: { coverage: coverage as unknown as Record<string, unknown>, targets: targets as unknown as Record<string, unknown> },
        },
        now,
      ),
    ]
  }

  // Gated ON — call the injected engine. It owns the real gate (consent↔digest,
  // SSRF pin, budget, attestation); the agent forwards and never fabricates a
  // binding. A throwing engine fails closed to a plan-only-style error claim.
  const ctx: VerifyContext = { authorized, allowPrivate: input.allowPrivate === true, missionId, now, consent: input.consent, resolveConsent: input.verifyConsent, onLog: log }
  let findings: VerifiedFinding[]
  try {
    log(`verify: running injected verifier over ${targets.length} target(s)…`)
    findings = await input.verify!.verify(targets, ctx)
  } catch (e) {
    const coverage: VerificationCoverage = {
      authorized, consentProvided, verifierPresent, ran: false,
      activelyTested: [], confirmed: [], observedOnly,
      note: `active verification attempted but the injected verifier failed: ${e instanceof Error ? e.message : String(e)} — nothing confirmed`,
    }
    return [
      newClaim({ missionId, goalId, sense: 'web', capability: 'verify.coverage', operation: 'verify', verdict: `active verification errored: ${e instanceof Error ? e.message : String(e)}`, confidence: 0.2, verification: { passed: false, method: coverage.note }, continuationState: { coverage: coverage as unknown as Record<string, unknown> } }, now),
    ]
  }

  const out: CognitiveClaim[] = []
  const activelyTested: VerificationCoverage['activelyTested'] = []
  const confirmed: VerificationCoverage['confirmed'] = []
  for (const f of findings) {
    const tgt = `${f.target.method ?? 'GET'} ${f.target.url}?${f.target.param}`
    activelyTested.push({ vulnKind: f.vulnKind, probe: f.probe, target: tgt, verdict: f.verdict })
    if (f.verdict !== 'confirmed') continue
    const receipt = f.attestation?.receipt ?? null
    confirmed.push({ vulnKind: f.vulnKind, target: tgt, receipt })
    const evid: Evidence[] = []
    // The demonstrated finding itself, in the [severity] kind: detail shape the
    // report parses — severity 'demonstrated', kind = the vuln class.
    evid.push(framed(`[demonstrated] ${f.vulnKind}: ${f.detail}`, f.target.url, f.engine ?? 'active-verifier', now))
    for (const e of f.evidence ?? []) evid.push(framed(`${e.label}: ${e.detail}`, f.target.url, f.engine ?? 'active-verifier', now))
    if (receipt) evid.push(framed(`attestation: ${receipt}${f.attestation?.digest ? ` (digest ${f.attestation.digest})` : ''}`, f.target.url, f.engine ?? 'active-verifier', now))
    out.push(
      newClaim(
        {
          missionId, goalId, sense: 'web', capability: 'verify.active', operation: 'verify',
          verdict: `EXPLOIT VERIFIED — ${f.vulnKind} on ${f.target.param} @ ${f.target.url}: ${f.detail}`,
          confidence: CONF[f.confidence ?? 'strong'] ?? 0.97,
          evidence: evid,
          entities: [{ id: `web:vuln:${f.vulnKind}:${f.target.url}:${f.target.param}`, sense: 'web', kind: 'vulnerability', label: `${f.vulnKind} @ ${f.target.param}` }],
          verification: { passed: true, method: `active ${f.probe} probe by ${f.engine ?? 'injected verifier'}${receipt ? ` — attestation ${receipt}` : ''}` },
          continuationState: { attestation: (f.attestation ?? null) as unknown as Record<string, unknown>, probe: f.probe, vulnKind: f.vulnKind },
          memoryCandidates: [{ kind: 'semantic', statement: `${f.vulnKind} DEMONSTRATED on ${f.target.url} param ${f.target.param}`, scope: f.target.url }],
        },
        now,
      ),
    )
  }

  const coverage: VerificationCoverage = {
    authorized, consentProvided, verifierPresent, ran: true,
    activelyTested, confirmed, observedOnly,
    note: confirmed.length
      ? `ACTIVELY tested ${activelyTested.length} target/probe(s); ${confirmed.length} DEMONSTRATED. All OTHER findings in this report are OBSERVED ONLY (static), not actively confirmed.`
      : `ACTIVELY tested ${activelyTested.length} target/probe(s); none confirmed. All findings remain OBSERVED ONLY (static).`,
  }
  log(`verify: ${confirmed.length}/${activelyTested.length} demonstrated`)
  out.push(
    newClaim(
      {
        missionId, goalId, sense: 'web', capability: 'verify.coverage', operation: 'verify',
        verdict: coverage.note,
        confidence: confirmed.length ? Math.max(USABLE_OBSERVATION_CONFIDENCE, 0.8) : 0.5,
        verification: { passed: confirmed.length > 0, method: coverage.note },
        continuationState: { coverage: coverage as unknown as Record<string, unknown> },
      },
      now,
    ),
  )
  return out
}
