import { newClaim, type CognitiveClaim, type Entity, type Evidence, type NextProbe } from '@dir-ai/voyager-contract'
import { stripInjection } from '@dir-ai/voyager'
import type { NetBrief } from '@dir-ai/voyager-net'
import type { OrientationBrief } from '@dir-ai/voyager-repo'
import type { PageBrief } from '@dir-ai/voyager-browser'
import { ERROR_CLAIM_CONFIDENCE } from './constants.js'

/** framed:true must be EARNED, not asserted. The senses already strip their
 *  target-controlled text, but the orchestrator re-strips here so a claim marked
 *  `framed` has actually been neutralized by THIS layer too — defense in depth,
 *  no "framed of convenience". */
function framedEvidence(what: string, at: string | undefined, source: string, capabilityId: string, now: number): Evidence {
  return { what: stripInjection(what).slice(0, 500), at: at ? stripInjection(at).slice(0, 200) : at, framed: true, provenance: { source, capabilityId, fetchedAt: now } }
}

const sevToConfidence: Record<string, number> = { critical: 0.95, high: 0.9, medium: 0.75, low: 0.6, info: 0.5 }

/** voyager-net's NetBrief → a CognitiveClaim the mission graph can reason over.
 *  A tool error becomes an `observe` claim flagged unknown, never a false verdict. */
export function netBriefToClaim(brief: NetBrief, missionId: string, now: number, goalId?: string): CognitiveClaim {
  if (brief.error) {
    return newClaim({ missionId, goalId, sense: 'net', capability: 'net.scan', operation: 'observe', verdict: `could not audit ${brief.target.input}: ${brief.error}`, confidence: ERROR_CLAIM_CONFIDENCE, unknowns: [brief.error] }, now)
  }
  const host = brief.target.host ?? brief.target.input
  const entities: Entity[] = [{ id: `net:host:${host}`, sense: 'net', kind: 'host', label: host }]
  const evidence: Evidence[] = []
  for (const p of brief.ports.filter((x) => x.state === 'open')) {
    entities.push({ id: `net:port:${host}:${p.port}`, sense: 'net', kind: 'port', label: `${p.port}${p.service ? `/${p.service}` : ''}` })
    if (p.product) entities.push({ id: `net:service:${p.product}${p.version ? `@${p.version}` : ''}`, sense: 'net', kind: 'service', label: `${p.product} ${p.version ?? ''}`.trim() })
  }
  for (const f of brief.findings) evidence.push(framedEvidence(`[${f.severity}] ${f.kind}: ${f.detail}`, f.at, 'voyager-net', 'net.scan', now))

  const worst = brief.findings.reduce((m, f) => Math.max(m, sevToConfidence[f.severity] ?? 0), 0)
  const nextProbes: NextProbe[] = brief.suggestedNextProbes.map((s) => ({ sense: 'net', description: s, expectedInformationGain: 0.4, cost: 3 }))

  return newClaim({
    missionId, goalId, sense: 'net', capability: 'net.scan', operation: 'observe',
    verdict: brief.summary,
    confidence: brief.findings.length ? Math.max(0.6, worst) : 0.7,
    evidence, entities, suggestedNextProbes: nextProbes,
    relationships: brief.ports.filter((p) => p.state === 'open' && p.product).map((p) => ({ from: `net:host:${host}`, to: `net:service:${p.product}${p.version ? `@${p.version}` : ''}`, kind: 'runs-on', confidence: 0.8 })),
    memoryCandidates: brief.findings.filter((f) => f.severity === 'high' || f.severity === 'critical').map((f) => ({ kind: 'semantic', statement: `${host}: ${f.detail}`, scope: host })),
  }, now)
}

/** voyager-repo's OrientationBrief → a CognitiveClaim. */
export function repoBriefToClaim(brief: OrientationBrief, missionId: string, now: number, goalId?: string): CognitiveClaim {
  if (brief.error) {
    return newClaim({ missionId, goalId, sense: 'repo', capability: 'repo.scout', operation: 'observe', verdict: `could not orient in the repo: ${brief.error}`, confidence: ERROR_CLAIM_CONFIDENCE, unknowns: [brief.error] }, now)
  }
  const name = brief.manifest?.name ?? brief.target.resolvedPath ?? 'repo'
  const entities: Entity[] = [{ id: `repo:project:${name}`, sense: 'repo', kind: 'project', label: name }]
  for (const e of brief.structure?.entrypoints ?? []) entities.push({ id: `repo:file:${e}`, sense: 'repo', kind: 'file', label: e })
  const evidence: Evidence[] = brief.risks.map((r) => framedEvidence(`[${r.level}] ${r.kind}: ${r.detail}`, r.path, 'voyager-repo', 'repo.scout', now))

  const rejectedDeps = brief.dependencies.findings.filter((d) => d.verdict === 'rejected')
  for (const d of rejectedDeps) entities.push({ id: `repo:dep:${d.name}`, sense: 'repo', kind: 'dep', label: d.name })
  const worstRisk = brief.risks.some((r) => r.level === 'high') || rejectedDeps.length ? 0.85 : brief.risks.length ? 0.7 : 0.65

  return newClaim({
    missionId, goalId, sense: 'repo', capability: 'repo.scout', operation: 'observe',
    verdict: brief.summary,
    confidence: worstRisk,
    evidence, entities,
    suggestedNextProbes: brief.suggestedNextProbe.map((s) => ({ sense: 'repo', description: s, expectedInformationGain: 0.35, cost: 2 })),
    relationships: rejectedDeps.map((d) => ({ from: `repo:project:${name}`, to: `repo:dep:${d.name}`, kind: 'depends-on', confidence: 0.9 })),
    unknowns: brief.approach.withheld.map((w) => `withheld until consent: ${w}`),
    memoryCandidates: rejectedDeps.map((d) => ({ kind: 'semantic', statement: `${name} depends on ${d.name} which Voyager rejected: ${d.note ?? 'unsafe'}`, scope: name })),
  }, now)
}

/** voyager-browser's PageBrief → a CognitiveClaim. A client-rendered page marks
 *  itself PARTIAL via an unknown, so the mission knows the static fetch saw a
 *  shell, not the SPA runtime. A tool error becomes a flagged-unknown observe. */
export function browserBriefToClaim(brief: PageBrief, missionId: string, now: number, goalId?: string): CognitiveClaim {
  if (brief.error) {
    return newClaim({ missionId, goalId, sense: 'web', capability: 'browser.observe', operation: 'observe', verdict: `could not observe ${brief.target.input}: ${brief.error}`, confidence: ERROR_CLAIM_CONFIDENCE, unknowns: [brief.error] }, now)
  }
  const origin = brief.target.origin ?? brief.target.url ?? brief.target.input
  const entities: Entity[] = [{ id: `web:page:${brief.target.url ?? origin}`, sense: 'web', kind: 'page', label: origin }]
  for (const o of brief.security?.thirdPartyScripts ?? []) entities.push({ id: `web:origin:${o}`, sense: 'web', kind: 'origin', label: o })
  for (const f of brief.forms.filter((x) => x.sensitive)) entities.push({ id: `web:form:${f.action}`, sense: 'web', kind: 'form', label: f.action })

  const evidence: Evidence[] = brief.findings.map((f) => framedEvidence(`[${f.severity}] ${f.kind}: ${f.detail}`, f.at, 'voyager-browser', 'browser.observe', now))
  const worst = brief.findings.reduce((m, f) => Math.max(m, sevToConfidence[f.severity] ?? 0), 0)

  const unknowns: string[] = []
  if (brief.render !== 'static') unknowns.push(`static fetch saw a ${brief.render} page — client-rendered content was NOT observed`)
  if (brief.truncated) unknowns.push('page body was truncated — observation is partial')

  return newClaim({
    missionId, goalId, sense: 'web', capability: 'browser.observe', operation: 'observe',
    verdict: brief.summary,
    confidence: brief.render !== 'static' || brief.truncated ? 0.5 : brief.findings.length ? Math.max(0.6, worst) : 0.7,
    evidence, entities, unknowns,
    suggestedNextProbes: brief.suggestedNextProbes.map((s) => ({ sense: 'web', description: s, expectedInformationGain: 0.35, cost: 2 })),
    relationships: (brief.security?.thirdPartyScripts ?? []).map((o) => ({ from: `web:page:${brief.target.url ?? origin}`, to: `web:origin:${o}`, kind: 'depends-on', confidence: 0.7 })),
    memoryCandidates: brief.findings.filter((f) => f.severity === 'high' || f.severity === 'critical').map((f) => ({ kind: 'semantic', statement: `${origin}: ${f.detail}`, scope: origin })),
  }, now)
}
