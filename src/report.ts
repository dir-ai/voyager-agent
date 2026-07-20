import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify, createPublicKey, createPrivateKey, type KeyObject } from 'node:crypto'
import type { MissionGraph } from '@dir-ai/voyager-contract'
import { VERSION } from './version.js'
import { complianceFor, controlTags } from './compliance.js'

/**
 * The client-grade artifact — a SARIF 2.1.0 report + a signature. Kimi's operative
 * gap: "the mission prints text — no timestamped, signed report; the client attestation
 * has no object." This turns a mission into a standard SARIF log (ingestible by GitHub
 * code-scanning, DefectDojo, etc.) AND carries an HONEST coverage statement (what was
 * tested, what was NOT) + a SHA-256 signature over the canonical report — the receipt
 * that says "tested against N controls on day X with outcome Y", never "impenetrable".
 */
const LEVEL: Record<string, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }

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
  for (const c of mission.allClaims()) {
    if (c.operation !== 'observe') continue
    for (const e of c.evidence) {
      const m = /^\[(\w+)\]\s*([a-z0-9-]+)\s*:\s*([\s\S]*)$/i.exec(e.what)
      const sev = (m?.[1] ?? 'info').toLowerCase()
      const kind = m?.[2] ?? 'finding'
      const detail = (m?.[3] ?? e.what).trim()
      ruleIds.add(`${c.sense}/${kind}`)
      const tags = controlTags(complianceFor(kind))
      results.push({
        ruleId: `${c.sense}/${kind}`,
        level: LEVEL[sev] ?? 'note',
        message: { text: detail.slice(0, 1000) },
        locations: e.at ? [{ physicalLocation: { artifactLocation: { uri: String(e.at).slice(0, 400) } } }] : [],
        // Compliance controls as SARIF tags — the CIS/OWASP/NIST vocabulary a CISO reports against.
        properties: { sense: c.sense, severity: sev, confidence: c.confidence, tags },
      })
    }
  }
  // Honest coverage: which senses ran + the mission's own verification verdict.
  const verify = mission.allClaims().find((x) => x.operation === 'verify')
  const coverage = verify?.verification?.method ?? 'see mission verification'
  const notTested = 'This report attests ONLY the controls Voyager tested (read-only introspection of the declared targets). It does NOT test: credentialed/authenticated access, business logic, 0-days, phishing/social, insider threat, or anything outside the declared scope. Absence of a finding within scope is not a guarantee of security.'

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'voyager-agent', version: VERSION, informationUri: 'https://github.com/dir-ai/voyager-agent', rules: [...ruleIds].map((id) => ({ id })) } },
        results,
        invocations: [{ executionSuccessful: true, endTimeUtc: new Date(opts.now).toISOString(), properties: { targets: opts.targets ?? [], coverage, satisfied: state.satisfied } }],
        properties: { coverageStatement: coverage, scopeDisclaimer: notTested, rootCause: state.rootCause?.cause ?? null },
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
