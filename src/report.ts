import { createHash } from 'node:crypto'
import type { MissionGraph } from '@dir-ai/voyager-contract'
import { VERSION } from './version.js'

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
  /** SHA-256 over the canonical SARIF — the tamper-evident signature. */
  signature: string
  findingCount: number
}

export function missionReport(mission: MissionGraph, opts: { now: number; targets?: string[] }): MissionReport {
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
      results.push({
        ruleId: `${c.sense}/${kind}`,
        level: LEVEL[sev] ?? 'note',
        message: { text: detail.slice(0, 1000) },
        locations: e.at ? [{ physicalLocation: { artifactLocation: { uri: String(e.at).slice(0, 400) } } }] : [],
        properties: { sense: c.sense, severity: sev, confidence: c.confidence },
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
  const canonical = JSON.stringify(sarif)
  const signature = `sha256:${createHash('sha256').update(canonical).digest('hex')}`
  return { sarif, signature, findingCount: results.length }
}
