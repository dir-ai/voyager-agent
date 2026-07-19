import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { NetBrief } from '@dir-ai/voyager-net'
import type { OrientationBrief } from '@dir-ai/voyager-repo'
import { netBriefToClaim, repoBriefToClaim } from '../dist/adapters.js'
import { DeterministicBrain } from '../dist/brain.js'
import { runMission } from '../dist/agent.js'

const NOW = 1_700_000_000_000

function netBrief(over: Partial<NetBrief> = {}): NetBrief {
  return {
    target: { input: 'example.com', host: 'example.com', kind: 'domain', scope: 'public' },
    resolvedIp: '93.0.0.1', authorized: true, summary: 'example.com — 1 finding(s); worst: high. 2 open port(s).',
    dns: null, ports: [], tls: [], http: [], findings: [], confidence: 'moderate',
    suggestedNextProbes: [], sanitization: { framedFields: 0 }, notes: [],
    ...over,
  } as NetBrief
}

function repoBrief(over: Partial<OrientationBrief> = {}): OrientationBrief {
  return {
    target: { input: '.', kind: 'local', resolvedPath: '/x/repo' },
    summary: 'acme@1.0.0 — a tool', purpose: null, manifest: null, structure: null,
    build: {} as OrientationBrief['build'],
    dependencies: { direct: 0, checked: 0, coverage: 'none', findings: [] },
    health: {} as OrientationBrief['health'], risks: [],
    approach: { repotector: 'absent', permissions: { read: true, install: false, exec: false, clone: false }, withheld: [], orderedNextSteps: [] },
    confidence: 'moderate', sanitization: { framedFields: 0, strippedPayloads: 0 }, suggestedNextProbe: [], notes: [],
    ...over,
  } as OrientationBrief
}

test('netBriefToClaim: error becomes an observe claim flagged unknown, not a false verdict', () => {
  const c = netBriefToClaim(netBrief({ error: 'not authorized.' }), 'm', NOW, 'g.observe')
  assert.equal(c.operation, 'observe')
  assert.equal(c.sense, 'net')
  assert.ok(c.unknowns.includes('not authorized.'))
  assert.ok(c.confidence < 0.3)
})

test('netBriefToClaim: open ports become entities, findings become framed evidence', () => {
  const c = netBriefToClaim(
    netBrief({
      ports: [{ port: 22, state: 'open', open: true, service: 'ssh', product: 'OpenSSH', version: '8.9' } as NetBrief['ports'][number]],
      findings: [{ severity: 'high', kind: 'exposed-service', detail: 'ssh reachable', at: 'example.com:22', suggestedFix: 'restrict', confidence: 'strong' } as NetBrief['findings'][number]],
    }),
    'm', NOW,
  )
  assert.ok(c.entities.some((e) => e.kind === 'host'))
  assert.ok(c.entities.some((e) => e.kind === 'port'))
  assert.ok(c.evidence.every((e) => e.framed === true)) // owner-controlled text arrives framed
  assert.ok(c.confidence >= 0.6)
  assert.ok(c.memoryCandidates.length >= 1) // high finding is memory-worthy
})

test('repoBriefToClaim: rejected dependency becomes a risk entity + memory + relationship', () => {
  const c = repoBriefToClaim(
    repoBrief({
      manifest: { name: 'acme', ecosystem: 'npm', directDependencies: ['evil'] } as OrientationBrief['manifest'],
      dependencies: { direct: 1, checked: 1, coverage: 'direct', findings: [{ name: 'evil', verdict: 'rejected', note: 'malware' }] },
      risks: [{ level: 'high', kind: 'unsafe-dependency', detail: 'evil is REJECTED' }],
    }),
    'm', NOW,
  )
  assert.ok(c.entities.some((e) => e.kind === 'dep' && e.label === 'evil'))
  assert.ok(c.relationships.some((r) => r.kind === 'depends-on' && r.to.includes('evil')))
  assert.ok(c.memoryCandidates.some((m) => m.statement.includes('evil')))
  assert.ok(c.confidence >= 0.85)
})

test('repoBriefToClaim: withheld actions surface as unknowns (consent-gated, never applied)', () => {
  const c = repoBriefToClaim(repoBrief({ approach: { repotector: 'absent', permissions: { read: true, install: false, exec: false, clone: false }, withheld: ['install dependencies'], orderedNextSteps: [] } }), 'm', NOW)
  assert.ok(c.unknowns.some((u) => u.includes('install dependencies')))
})

test('DeterministicBrain: decompose yields an ordered observe→assess→conclude arc', () => {
  const goals = new DeterministicBrain().decompose('audit acme', 'm')
  assert.deepEqual(goals.map((g) => g.id), ['g.observe', 'g.assess', 'g.conclude'])
  assert.ok(goals[1].dependsOn.includes('g.observe'))
})

test('DeterministicBrain: synthesize fuses observations into one infer claim', () => {
  const brain = new DeterministicBrain()
  const obs = netBriefToClaim(
    netBrief({ findings: [{ severity: 'high', kind: 'x', detail: 'bad', at: 'h:1', suggestedFix: 'f', confidence: 'strong' } as NetBrief['findings'][number]] }),
    'm', NOW, 'g.observe',
  )
  const inferred = brain.synthesize('audit', 'm', [obs], NOW)
  assert.equal(inferred.operation, 'infer')
  assert.ok(/high|critical/i.test(inferred.verdict) || inferred.evidence.length >= 1)
})

test('runMission: with no senses requested, still concludes (low-confidence infer), no throw', async () => {
  const { mission } = await runMission('understand nothing in particular', {}, NOW)
  const claims = mission.allClaims()
  assert.equal(claims.length, 1) // just the synthesized infer
  assert.equal(claims[0].operation, 'infer')
  assert.ok(mission.state().satisfied === false || mission.state().openGoals.length === 0)
})
