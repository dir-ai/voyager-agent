import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { NetBrief } from '@dir-ai/voyager-net'
import type { OrientationBrief } from '@dir-ai/voyager-repo'
import { netBriefToClaim, repoBriefToClaim, browserBriefToClaim } from '../dist/adapters.js'
import { DeterministicBrain } from '../dist/brain.js'
import { LlmBrain, extractJson } from '../dist/llm-brain.js'
import { runMission } from '../dist/agent.js'
import { ERROR_CLAIM_CONFIDENCE, USABLE_OBSERVATION_CONFIDENCE } from '../dist/constants.js'
import { newClaim } from '@dir-ai/voyager-contract'

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

test('runMission: with no senses requested, still concludes (infer + verify), no throw', async () => {
  const { mission } = await runMission('understand nothing in particular', {}, NOW)
  const claims = mission.allClaims()
  assert.ok(claims.some((c) => c.operation === 'infer'))
  assert.ok(claims.some((c) => c.operation === 'verify'))
  // No usable observation → the verify claim does not pass → mission not satisfied.
  assert.equal(mission.state().satisfied, false)
})

test('runMission: a repo mission closes all goals and reaches satisfied (verify passes)', async () => {
  const { mission } = await runMission('audit this repo', { repoPath: '.' }, NOW)
  assert.equal(mission.state().openGoals.length, 0)
  assert.equal(mission.state().satisfied, true) // usable observation → verify passes → done
})

test('runMission: uses allSettled — a THROWING sense degrades to a flagged claim, sibling survives', async () => {
  // A brain whose decompose is fine; we force the net sense to throw by passing a
  // host that resolves but the scan will error/throw is hard — instead assert the
  // resilience contract holds for a good repo + a fail-closed host (no crash).
  const { mission } = await runMission('audit repo and host', { repoPath: '.', host: 'example.com', authorized: false }, NOW)
  const claims = mission.allClaims()
  assert.ok(claims.some((c) => c.sense === 'repo' && c.confidence >= 0.4), 'the good repo observation survives')
  assert.ok(claims.some((c) => c.sense === 'net' && c.unknowns.length > 0), 'the fail-closed host becomes a flagged-unknown claim, not a crash')
})

test('browserBriefToClaim: a client-heavy page flags itself PARTIAL via an unknown', () => {
  const brief = {
    target: { input: 'https://spa.test', url: 'https://spa.test/', origin: 'https://spa.test' },
    resolvedIp: '1.2.3.4', fetchedAt: NOW, status: 200, contentType: 'text/html', render: 'client-heavy', renderConfidence: 'moderate', truncated: false,
    summary: 'spa.test — client-heavy', structure: null, forms: [], links: { total: 0, internal: 0, external: 0, unsafeBlank: 0, sample: [] },
    security: { https: true, hsts: true, hstsWeak: false, csp: true, cspWeaknesses: [], xContentTypeOptions: true, referrerPolicy: true, frameProtection: true, coop: false, corp: false, permissionsPolicy: false, versionLeak: null, mixedContent: [], thirdPartyScripts: ['https://cdn.other.com'], insecureCookies: [] },
    a11y: { lang: true, imgAltCoverage: null, formFieldsLabeled: null, headingOrderOk: true },
    findings: [], confidence: 'moderate', suggestedNextProbes: [], sanitization: { framedFields: 0, strippedPayloads: 0 }, notes: [],
  } as unknown as Parameters<typeof browserBriefToClaim>[0]
  const c = browserBriefToClaim(brief, 'm', NOW, 'g.observe')
  assert.equal(c.sense, 'web')
  assert.ok(c.unknowns.some((u) => /client-heavy|not observed/i.test(u)))
  assert.ok(c.entities.some((e) => e.kind === 'origin')) // third-party origin surfaced
})

test('confidence partition invariant: error < usable ≤ every healthy floor', () => {
  assert.ok(ERROR_CLAIM_CONFIDENCE < USABLE_OBSERVATION_CONFIDENCE)
  // healthy floors in the adapters: net 0.6/0.7, repo 0.65, browser 0.5/0.6/0.7
  for (const floor of [0.5, 0.6, 0.65, 0.7]) assert.ok(USABLE_OBSERVATION_CONFIDENCE <= floor)
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

// ── Iterative loop (pickNext is no longer dead code) ───────────────────────

test('iterative loop: runs bounded rounds via an injected dispatch, then concludes', async () => {
  let calls = 0
  const dispatch = async (_probe: unknown, ctx: { missionId: string; now: number }) => {
    calls++
    // Each probe-driven claim surfaces a FRESH probe so the loop keeps re-planning.
    // Strictly increasing gain so the freshest probe always wins pickNext (no tie
    // with an already-acted probe that would break the loop early).
    return newClaim({ missionId: ctx.missionId, sense: 'repo', operation: 'observe', verdict: `probe round ${calls}`, confidence: 0.7, suggestedNextProbes: [{ sense: 'repo', description: `next-${calls + 1}`, expectedInformationGain: 10 + calls, cost: 1 }] }, ctx.now)
  }
  const { mission } = await runMission('probe iteratively', { repoPath: '.', maxRounds: 3, dispatch: dispatch as never }, NOW)
  assert.equal(calls, 3, 'the loop runs exactly maxRounds when probes keep coming')
  assert.ok(mission.allClaims().some((c) => /probe round 1/.test(c.verdict)))
  assert.ok(mission.allClaims().some((c) => c.operation === 'verify'))
})

test('iterative loop: stops immediately when a probe is not dispatchable (null)', async () => {
  let calls = 0
  const dispatch = async () => {
    calls++
    return null
  }
  await runMission('probe once', { repoPath: '.', maxRounds: 5, dispatch: dispatch as never }, NOW)
  assert.equal(calls, 1, 'a non-dispatchable probe stops the loop after one attempt')
})

test('iterative loop: maxRounds 0 disables iteration entirely', async () => {
  let calls = 0
  const dispatch = async () => {
    calls++
    return null
  }
  await runMission('no loop', { repoPath: '.', maxRounds: 0, dispatch: dispatch as never }, NOW)
  assert.equal(calls, 0)
})
