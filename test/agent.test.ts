import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { NetBrief } from '@dir-ai/voyager-net'
import type { OrientationBrief } from '@dir-ai/voyager-repo'
import { netBriefToClaim, repoBriefToClaim } from '../dist/adapters.js'
import { DeterministicBrain } from '../dist/brain.js'
import { LlmBrain, extractJson } from '../dist/llm-brain.js'
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

test('extractJson: pulls JSON out of fences and surrounding prose', () => {
  assert.deepEqual(extractJson('```json\n{"a":1}\n```'), { a: 1 })
  assert.deepEqual(extractJson('Sure! Here you go: [{"id":"g1"}] hope that helps'), [{ id: 'g1' }])
  assert.deepEqual(extractJson('{"nested":{"x":[1,2]}}'), { nested: { x: [1, 2] } })
  assert.equal(extractJson('no json here'), null)
})

test('LlmBrain.decomposeAsync: uses the model when it returns valid goals', async () => {
  const brain = new LlmBrain({ complete: async () => '[{"id":"g.scope","statement":"scope it","dependsOn":[]},{"id":"g.act","statement":"do it","dependsOn":["g.scope"]}]' })
  const goals = await brain.decomposeAsync('anything', 'm')
  assert.deepEqual(goals.map((g) => g.id), ['g.scope', 'g.act'])
  assert.equal(goals[0].missionId, 'm')
  assert.ok(goals[1].dependsOn.includes('g.scope'))
})

test('LlmBrain.decomposeAsync: FAILS SAFE to the deterministic arc on garbage output', async () => {
  let reason = ''
  const brain = new LlmBrain({ complete: async () => 'I refuse to answer', onFallback: (_s, r) => { reason = r } })
  const goals = await brain.decomposeAsync('x', 'm')
  assert.deepEqual(goals.map((g) => g.id), ['g.observe', 'g.assess', 'g.conclude']) // deterministic fallback
  assert.ok(reason.length > 0)
})

test('LlmBrain.synthesizeAsync: takes the model verdict + confidence, keeps the structured graph', async () => {
  const obs = netBriefToClaim(
    netBrief({ ports: [{ port: 443, state: 'open', open: true, service: 'https', product: 'nginx', version: '1.25' } as NetBrief['ports'][number]], findings: [{ severity: 'high', kind: 'weak-tls', detail: 'TLS 1.0', at: 'h:443', suggestedFix: 'x', confidence: 'strong' } as NetBrief['findings'][number]] }),
    'm', NOW, 'g.observe',
  )
  const brain = new LlmBrain({ complete: async () => '{"verdict":"nginx exposes weak TLS; rotate to 1.2+","confidence":0.82,"attention":true}' })
  const inferred = await brain.synthesizeAsync('audit', 'm', [obs], NOW)
  assert.equal(inferred.operation, 'infer')
  assert.match(inferred.verdict, /weak TLS/)
  assert.equal(inferred.confidence, 0.82)
  assert.ok(inferred.entities.length >= 1) // structured graph preserved from the deterministic fusion
})

test('LlmBrain.synthesizeAsync: FAILS SAFE to deterministic fusion when the model throws', async () => {
  const obs = netBriefToClaim(netBrief({ findings: [] }), 'm', NOW, 'g.observe')
  let stage = ''
  const brain = new LlmBrain({ complete: async () => { throw new Error('model down') }, onFallback: (s) => { stage = s } })
  const inferred = await brain.synthesizeAsync('audit', 'm', [obs], NOW)
  assert.equal(inferred.operation, 'infer')
  assert.equal(stage, 'synthesize')
})

test('runMission: an LlmBrain drives decompose + synthesize through the async path', async () => {
  const calls: string[] = []
  const brain = new LlmBrain({
    complete: async (msgs) => {
      const sys = msgs[0].content
      if (/planner/i.test(sys)) { calls.push('decompose'); return '[{"id":"g.observe","statement":"look","dependsOn":[]}]' }
      calls.push('synthesize'); return '{"verdict":"nothing observed, as expected","confidence":0.3,"attention":false}'
    },
  })
  // A real observation (this very repo) so synthesize has something to fuse —
  // with zero observations, synthesize correctly short-circuits without the model.
  const { mission } = await runMission('probe this repo', { brain, repoPath: '.' }, NOW)
  assert.deepEqual(calls, ['decompose', 'synthesize'])
  const infer = mission.allClaims().find((c) => c.operation === 'infer')
  assert.ok(infer)
  assert.match(infer!.verdict, /nothing observed/) // the model's verdict won
})
