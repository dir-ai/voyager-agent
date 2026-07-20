import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify, createPublicKey, createPrivateKey, type KeyObject } from 'node:crypto'
import type { MissionGraph } from '@dir-ai/voyager-contract'
import { stripInjection } from '@dir-ai/voyager'
import { VERSION } from './version.js'
import { complianceFor, controlTags } from './compliance.js'
import { nextMovesFor } from './next-moves.js'

/**
 * P0 (Kimi, verified live): the signed SARIF must NEVER embed target-derived text
 * raw. A repo file named `evil-<img src=x onerror=alert(1)>.js`, a banner, a URL or
 * a param flows through a claim verdict/evidence into `message.text` — and the
 * ed25519 signature would then AUTHENTICATE hostile, renderable markup. Every string
 * that enters the report passes through `san`: the family sanitizer `stripInjection`
 * (neutralizes prompt-injection phrasing) FOLLOWED BY HTML-neutralization (so a
 * viewer that renders message.text as HTML cannot execute injected markup). `deepSan`
 * applies it to every string in a nested structure (the coverage object). Nothing
 * target-derived reaches the signed bytes un-neutralized.
 */
function htmlInert(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}
function san(s: unknown): string {
  return htmlInert(stripInjection(String(s ?? '')))
}
function deepSan<T>(v: T): T {
  if (typeof v === 'string') return san(v) as unknown as T
  if (Array.isArray(v)) return v.map((x) => deepSan(x)) as unknown as T
  if (v && typeof v === 'object') {
    const o: Record<string, unknown> = {}
    for (const [k, val] of Object.entries(v)) o[k] = deepSan(val)
    return o as unknown as T
  }
  return v
}

/**
 * The client-grade artifact — a SARIF 2.1.0 report + a signature. Kimi's operative
 * gap: "the mission prints text — no timestamped, signed report; the client attestation
 * has no object." This turns a mission into a standard SARIF log (ingestible by GitHub
 * code-scanning, DefectDojo, etc.) AND carries an HONEST coverage statement (what was
 * tested, what was NOT) + a SHA-256 signature over the canonical report — the receipt
 * that says "tested against N controls on day X with outcome Y", never "impenetrable".
 */
const LEVEL: Record<string, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note', demonstrated: 'error' }

export interface MissionReport {
  sarif: unknown
  /** An Ed25519 signature (base64) over the canonical report — AUTHENTICITY, not just
   *  integrity: forging findings and re-hashing no longer produces a valid artifact
   *  (Kimi R3-7). Verify with the embedded public key + verifyReport(). */
  signature: string
  /** The Ed25519 public key (SPKI PEM) needed to verify — embedded in the SARIF too. */
  publicKey: string
  /** sha256 fingerprint of the public key — publish this out of band as the anchor. */
  keyFingerprint: string
  findingCount: number
}

/** A stable signer: a PEM Ed25519 private key (from a vault) → a persistent identity.
 *  Omit it and the report is signed with an EPHEMERAL key (still tamper-evident, but
 *  bind a stable key for cross-report authenticity). */
export interface SignOptions {
  privateKeyPem?: string
}

export function missionReport(mission: MissionGraph, opts: { now: number; targets?: string[]; sign?: SignOptions }): MissionReport {
  const state = mission.state()
  // Gather findings from observed evidence: [sev] kind: detail @ at.
  const results: Array<Record<string, unknown>> = []
  const ruleIds = new Set<string>()
  // The finding→move graph, aggregated for the run: ruleId → the analyst's next
  // moves (ADVICE only). Deduped so the run-level kill-chain lists each edge once.
  const killChain = new Map<string, { ruleId: string; sense: string; kind: string; suggestedNextProbes: string[] }>()
  for (const c of mission.allClaims()) {
    if (c.operation !== 'observe') continue
    for (const e of c.evidence) {
      const m = /^\[(\w+)\]\s*([a-z0-9-]+)\s*:\s*([\s\S]*)$/i.exec(e.what)
      const sev = (m?.[1] ?? 'info').toLowerCase()
      const kind = m?.[2] ?? 'finding'
      const detail = (m?.[3] ?? e.what).trim()
      // Tags are looked up on the RAW (regex-constrained) kind; the ruleId embedded
      // in the doc is sanitized. Everything target-derived (detail, at) is sanitized.
      const tags = controlTags(complianceFor(kind))
      const ruleId = san(`${c.sense}/${kind}`)
      ruleIds.add(ruleId)
      // FINDING→MOVE (advice, not execution): the concrete next probe(s) an analyst
      // would run to escalate this finding. Authored strings, still sanitized before
      // they enter the signed doc. Nothing is sent — this is the read-only agent.
      const moves = nextMovesFor(c.sense, kind).map((s) => san(s).slice(0, 400))
      if (!killChain.has(ruleId)) killChain.set(ruleId, { ruleId, sense: san(c.sense), kind: san(kind), suggestedNextProbes: moves })
      results.push({
        ruleId,
        level: LEVEL[sev] ?? 'note',
        message: { text: san(detail).slice(0, 1000) },
        locations: e.at ? [{ physicalLocation: { artifactLocation: { uri: san(e.at).slice(0, 400) } } }] : [],
        // Compliance controls as SARIF tags — the CIS/OWASP/NIST vocabulary a CISO reports against.
        // suggestedNextProbes: the ADVISORY escalation move(s) for THIS finding-kind.
        properties: { sense: san(c.sense), severity: sev, confidence: c.confidence, tags, suggestedNextProbes: moves },
      })
    }
  }
  // ── exploit-verified: DEMONSTRATED findings from an injected active verifier.
  // A distinct finding-kind (rule `<sense>/exploit-verified`) at DEMONSTRATED
  // severity → SARIF level 'error', flagged `demonstrated:true` so it is never
  // confused with a statically-observed finding. The engine is injected; this
  // package only ADAPTS its confirmed results — it performs no exploitation.
  // DEMONSTRATED findings that WERE actively chained (by an injected, consent-gated
  // verifier) — the honest "what WAS chained" set for the executedProbes note.
  const chained: Array<{ vulnKind: string; ruleId: string; attestation: string | null }> = []
  for (const c of mission.allClaims()) {
    if (c.capability !== 'verify.active' || c.operation !== 'verify' || c.verification?.passed !== true) continue
    // The lead evidence is `[demonstrated] <vulnKind>: <detail>`; any others are
    // reproducible sub-evidence (differential / marker / DB signature / receipt).
    const lead = c.evidence[0]
    const m = lead ? /^\[(\w+)\]\s*([a-z0-9-]+)\s*:\s*([\s\S]*)$/i.exec(lead.what) : null
    const vulnKindRaw = m?.[2] ?? ((c.continuationState?.vulnKind as string) ?? 'exploit')
    const detail = (m?.[3] ?? c.verdict).trim()
    const ruleId = san(`${c.sense}/exploit-verified`)
    ruleIds.add(ruleId)
    // Control lookup on the RAW vuln class; the value embedded in the doc is sanitized.
    const tags = controlTags(complianceFor(vulnKindRaw) ?? complianceFor('exploit-verified'))
    const receipt = (c.continuationState?.attestation as { receipt?: string } | null)?.receipt ?? null
    // Post-exploitation advice for a demonstrated finding — still ADVICE (the further
    // chaining is the hands engine's job, consent-gated, out of scope here).
    const moves = nextMovesFor(c.sense, vulnKindRaw).map((s) => san(s).slice(0, 400))
    if (!killChain.has(ruleId)) killChain.set(ruleId, { ruleId, sense: san(c.sense), kind: san('exploit-verified'), suggestedNextProbes: moves })
    chained.push({ vulnKind: san(vulnKindRaw), ruleId, attestation: receipt ? san(receipt) : null })
    results.push({
      ruleId,
      level: 'error',
      message: { text: san(detail).slice(0, 1000) },
      locations: lead?.at ? [{ physicalLocation: { artifactLocation: { uri: san(lead.at).slice(0, 400) } } }] : [],
      properties: {
        sense: san(c.sense), severity: 'demonstrated', demonstrated: true, vulnKind: san(vulnKindRaw), confidence: c.confidence, tags,
        attestation: receipt ? san(receipt) : null, method: c.verification?.method ? san(c.verification.method) : null,
        evidence: c.evidence.slice(1).map((e) => san(e.what).slice(0, 300)),
        suggestedNextProbes: moves,
      },
    })
  }

  // ── Coverage: the honest scope statement — what was ACTIVELY tested vs only
  // OBSERVED. Kimi's sharpest point: authenticity must not outrun the measured
  // perimeter, so the signed artifact declares its own scope. Read from the
  // active-verification coverage claim (if any).
  const covClaim = mission.allClaims().find((x) => x.capability === 'verify.coverage' && x.operation === 'verify')
  // The coverage object carries target-derived strings (URLs/params) — deep-sanitize
  // every string before it enters the signed doc.
  const activeCoverage = covClaim?.continuationState?.coverage ? deepSan(covClaim.continuationState.coverage as Record<string, unknown>) : null

  // Honest coverage: which senses ran + the mission's own verification verdict.
  // The FIRST verify claim is the required-sense coverage; skip the active-verify
  // coverage claims (they carry the `verify.coverage`/`verify.active` capability).
  const verify = mission.allClaims().find((x) => x.operation === 'verify' && x.capability !== 'verify.coverage' && x.capability !== 'verify.active')
  const coverage = san(verify?.verification?.method ?? 'see mission verification')
  const notTested = 'This report attests ONLY the controls Voyager tested (read-only introspection of the declared targets). It does NOT test: credentialed/authenticated access, business logic, 0-days, phishing/social, insider threat, or anything outside the declared scope. Absence of a finding within scope is not a guarantee of security.'

  // ── The kill chain (ADVICE): every finding-kind → the analyst's next move(s).
  // Turns the SARIF from a shopping list into an escalation plan WITHOUT executing
  // anything. `executedProbes` is the honest split: what the mission ACTUALLY chained
  // (only the consent-gated active-verification path can, and only when injected) vs
  // what remains an operator HYPOTHESIS. This read-only agent SUGGESTS the move; the
  // offensive execution is the separate `voyager-hands` engine (out of scope here).
  const suggestedNextProbes = [...killChain.values()]
  const executedProbes = {
    chained,
    chainedCount: chained.length,
    note: chained.length
      ? 'Only the actively-verified findings were CHAINED, via an injected, consent-gated verifier (see activeVerification). Every entry in suggestedNextProbes that is NOT listed here is an ADVISORY hypothesis for the operator — this read-only agent did not execute it.'
      : 'NOTHING was chained: all entries in suggestedNextProbes are ADVISORY hypotheses for the operator. This read-only agent SUGGESTS the next move in words; it sends no payloads and executes no probes. Offensive execution is the separate consent-gated voyager-hands engine (out of scope for this package).',
  }

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'voyager-agent', version: VERSION, informationUri: 'https://github.com/dir-ai/voyager-agent', rules: [...ruleIds].map((id) => ({ id })) } },
        results,
        invocations: [{ executionSuccessful: true, endTimeUtc: new Date(opts.now).toISOString(), properties: { targets: (opts.targets ?? []).map((t) => san(t)), coverage, satisfied: state.satisfied } }],
        properties: {
          coverageStatement: coverage,
          scopeDisclaimer: notTested,
          rootCause: state.rootCause?.cause ? san(state.rootCause.cause) : null,
          // The active-verification scope: which classes were ACTIVELY tested (and
          // demonstrated) vs which are OBSERVED ONLY. Absent when no verifier ran.
          activeVerification: activeCoverage ?? { ran: false, note: 'no active verification — all findings are OBSERVED ONLY (read-only introspection). Inject a consent-gated verifier to actively demonstrate suspected web vulns.' },
          // THE KILL CHAIN (advice, not execution): finding-kind → next escalation
          // move(s) with the named technique, plus the honest executed-vs-advisory split.
          suggestedNextProbes,
          executedProbes,
        },
      },
    ],
  }
  // Ed25519 SIGNATURE over the canonical report (before the signature block is added).
  // A stable vault key gives a persistent identity; else an ephemeral one is minted.
  const { privateKey, publicKey } = opts.sign?.privateKeyPem
    ? (() => { const priv = createPrivateKey(opts.sign!.privateKeyPem!); return { privateKey: priv, publicKey: createPublicKey(priv) } })()
    : generateKeyPairSync('ed25519')
  const canonical = JSON.stringify(sarif)
  const digest = createHash('sha256').update(canonical).digest('hex')
  const signature = edSign(null, Buffer.from(canonical), privateKey).toString('base64')
  const publicKeyPem = (publicKey as KeyObject).export({ type: 'spki', format: 'pem' }).toString()
  const keyFingerprint = keyFp(publicKey as KeyObject)
  // Embed the attestation + the KEY FINGERPRINT. Authenticity requires the verifier to
  // supply the anchor key OUT OF BAND (a fingerprint alone, or a key from the document,
  // can be swapped — Kimi F3). The embedded key/fingerprint are a convenience, not the
  // trust root: verifyReport authenticates ONLY against a caller-supplied anchor.
  ;(sarif.runs[0].properties as Record<string, unknown>).attestation = {
    alg: 'ed25519', signature, publicKey: publicKeyPem, keyFingerprint, sha256: digest, signedAt: new Date(opts.now).toISOString(),
    trustModel: 'AUTHENTICITY requires an out-of-band anchor key: verifyReport(sarif, { anchorPublicKeyPem }). The embedded key proves only internal integrity — a swapped key + re-sign (F3) yields integrity:true but authentic:false. Publish the dir-ai key on npm/GitHub/DNS TXT and pin its fingerprint.',
    note: opts.sign?.privateKeyPem ? 'signed with a bound key' : 'signed with an EPHEMERAL key — bind a stable vault key + publish its fingerprint for authenticity',
  }
  return { sarif, signature, publicKey: publicKeyPem, keyFingerprint, findingCount: results.length }
}

function keyFp(key: KeyObject): string {
  return 'sha256:' + createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 32)
}

export interface VerifyResult {
  /** The signature verifies against the key embedded in the document — the report was
   *  not tampered after whoever holds THAT key signed it. NOT proof of WHO. */
  integrity: boolean
  /** The signature verifies against the caller-supplied ANCHOR key — proof it was
   *  signed by the holder of the anchor's private key. Defeats the F3 key-swap. */
  authentic: boolean
  keyFingerprint: string | null
  reason: string
}

/**
 * Verify a report's Ed25519 attestation with the correct TRUST MODEL (Kimi F3 fix).
 * `integrity` checks the signature against the key embedded in the document — but an
 * attacker can forge findings, re-sign with THEIR key, and embed it, so integrity
 * alone is worthless for authenticity. `authentic` is true ONLY when the caller
 * supplies the expected anchor public key (published out of band) and the signature
 * verifies against IT — the attacker doesn't hold the anchor's private key, so the
 * key-swap forgery yields authentic:false.
 */
export function verifyReport(sarif: unknown, opts: { anchorPublicKeyPem?: string } = {}): VerifyResult {
  const fail = (reason: string): VerifyResult => ({ integrity: false, authentic: false, keyFingerprint: null, reason })
  try {
    const s = sarif as { runs?: Array<{ properties?: Record<string, unknown> }> }
    const props = s.runs?.[0]?.properties
    const att = props?.attestation as { alg?: string; signature?: string; publicKey?: string; keyFingerprint?: string } | undefined
    if (!props || !att?.signature || !att.publicKey || att.alg !== 'ed25519') return fail('no verifiable Ed25519 attestation present')
    const clone = JSON.parse(JSON.stringify(sarif)) as typeof s
    delete clone.runs![0].properties!.attestation
    const canonical = JSON.stringify(clone)
    const sig = Buffer.from(att.signature, 'base64')
    const embedded = createPublicKey(att.publicKey)
    const integrity = edVerify(null, Buffer.from(canonical), embedded, sig)
    const fp = keyFp(embedded)
    if (!opts.anchorPublicKeyPem) {
      return { integrity, authentic: false, keyFingerprint: fp, reason: integrity ? 'INTEGRITY only — no anchor key supplied; the signer is unauthenticated (self-signed). Pass { anchorPublicKeyPem } to authenticate.' : 'signature does not verify even against the embedded key — tampered' }
    }
    // Authenticity: the signature must verify against the ANCHOR key, not the embedded one.
    const anchor = createPublicKey(opts.anchorPublicKeyPem)
    const authentic = edVerify(null, Buffer.from(canonical), anchor, sig)
    return { integrity, authentic, keyFingerprint: fp, reason: authentic ? 'AUTHENTIC — signed by the anchor key holder' : 'NOT authentic — the signature does not verify against the supplied anchor key (key-swap forgery or wrong signer)' }
  } catch {
    return fail('verification error')
  }
}
