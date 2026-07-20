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
  // Embed the attestation so the artifact is self-verifiable (verifyReport()).
  ;(sarif.runs[0].properties as Record<string, unknown>).attestation = {
    alg: 'ed25519', signature, publicKey: publicKeyPem, sha256: digest, signedAt: new Date(opts.now).toISOString(),
    note: opts.sign?.privateKeyPem ? 'signed with a bound key' : 'signed with an EPHEMERAL key — bind a stable vault key for cross-report authenticity',
  }
  return { sarif, signature, publicKey: publicKeyPem, findingCount: results.length }
}

/**
 * Verify a report's embedded Ed25519 attestation. Recomputes the canonical report
 * WITHOUT the attestation block and checks the signature against the embedded public
 * key. Returns true only if the artifact is untampered — forging a finding and
 * re-hashing (the Kimi R3-7 attack) now FAILS here.
 */
export function verifyReport(sarif: unknown): boolean {
  try {
    const s = sarif as { runs?: Array<{ properties?: Record<string, unknown> }> }
    const props = s.runs?.[0]?.properties
    const att = props?.attestation as { alg?: string; signature?: string; publicKey?: string } | undefined
    if (!props || !att?.signature || !att.publicKey || att.alg !== 'ed25519') return false
    const clone = JSON.parse(JSON.stringify(sarif)) as typeof s
    delete clone.runs![0].properties!.attestation
    const canonical = JSON.stringify(clone)
    return edVerify(null, Buffer.from(canonical), createPublicKey(att.publicKey), Buffer.from(att.signature, 'base64'))
  } catch {
    return false
  }
}
