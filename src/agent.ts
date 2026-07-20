import { CapabilityGraph, MissionGraph, newClaim, seedFamilyCapabilities, type CognitiveClaim, type NextProbe } from '@dir-ai/voyager-contract'
import { scan } from '@dir-ai/voyager-net'
import { scout } from '@dir-ai/voyager-repo'
import { observe } from '@dir-ai/voyager-browser'
import { browserBriefToClaim, netBriefToClaim, repoBriefToClaim } from './adapters.js'
import { proposeRemediations } from './remediation.js'
import { correlate } from './correlate.js'
import { diffBaseline, saveBaseline, driftClaim, missionKey } from './baseline.js'
import { DeterministicBrain, dedupeProbes, type Brain } from './brain.js'
import { ERROR_CLAIM_CONFIDENCE, USABLE_OBSERVATION_CONFIDENCE } from './constants.js'

export interface MissionInput {
  /** A local repo path to orient in (via voyager-repo). */
  repoPath?: string
  /** A host/domain you own to audit (via voyager-net). */
  host?: string
  /** A live URL to observe (via voyager-browser). */
  url?: string
  /** MULTI-TARGET: audit several repos/hosts/URLs in ONE mission, correlated in the
   *  same MissionGraph (Kimi #10). Merged with the singular fields above. */
  repoPaths?: string[]
  hosts?: string[]
  urls?: string[]
  /** REQUIRED to actually scan the host (voyager-net's fail-closed gate). */
  authorized?: boolean
  /** Ports for the net scan — open the sense wider than the default sweep (Kimi A3).
   *  e.g. a top-1000 or a custom list. Passed straight through to voyager-net. */
  ports?: number[]
  /** Per-probe timeout (ms) for the net sense. */
  timeoutMs?: number
  /** Verify up to N dependencies via Voyager during the repo scout. */
  checkDeps?: number
  /** WRAP external coverage engines (trivy/semgrep) during the repo scout if on PATH,
   *  adapting their output into framed findings under the gate. Opt-in (slow). */
  wrapScanners?: boolean
  /** Track DRIFT across audits: a directory where the target set's baseline is
   *  persisted. On the next run it reports NEW / RESOLVED / unchanged findings —
   *  "what changed since last time". Off unless set. */
  baselineDir?: string
  /** HMAC key (from the vault) that SEALS the drift baseline — a hand-rewritten
   *  baseline fails verification and is refused (fail-closed). Strongly recommended
   *  whenever baselineDir is set. */
  baselineKey?: string
  /** The reasoning model. Defaults to a rule-based brain so it runs with no LLM. */
  brain?: Brain
  /** Max rounds of iterative probing AFTER the initial observe (default 2, 0 = off). */
  maxRounds?: number
  /** Propose consent-gated (withheld) remediations for remediable findings via the
   *  HANDS. Default true; the proposals are always withheld, never applied. */
  remediate?: boolean
  /** Execute a chosen next-probe against a real sense, returning a new claim (or
   *  null to stop iterating). Injected so the reasoning model decides HOW to run a
   *  probe; the safe default only deepens repo dependency-vetting. */
  dispatch?: (probe: NextProbe, ctx: ProbeContext) => Promise<CognitiveClaim | null>
  onLog?: (line: string) => void
}

export interface ProbeContext {
  intent: string
  input: MissionInput
  missionId: string
  now: number
  /** The live mission — dispatch can read discovered entities to aim the next
   *  probe (e.g. an HTTP service the net sense found → a page the browser observes). */
  mission: MissionGraph
}

export interface MissionRun {
  capabilities: CapabilityGraph
  mission: MissionGraph
}

/** One sense job: always resolves to a claim — a thrown sense degrades to a
 *  flagged-unknown observe claim exactly like an error brief (never crashes the
 *  mission, never loses a sibling sense's good observation). */
function senseJob(sense: CognitiveClaim['sense'], capability: string, run: () => Promise<CognitiveClaim>, now: number, missionId: string, goalId?: string): Promise<CognitiveClaim> {
  return run().catch((e: unknown) =>
    newClaim({ missionId, goalId, sense, capability, operation: 'observe', verdict: `${capability} failed unexpectedly: ${e instanceof Error ? e.message : String(e)}`, confidence: ERROR_CLAIM_CONFIDENCE, unknowns: [e instanceof Error ? e.message : String(e)] }, now),
  )
}

/**
 * The capability-driven probe executor: it turns the model's routed next-probe
 * into a REAL cross-sense observation, staying strictly inside the safe envelope.
 *  - repo → a deeper, read-only dependency-vetting pass.
 *  - web  → observe a page: the URL the caller gave, or — the net→browser handoff —
 *           the web surface of the AUTHORIZED host the net sense just scanned. This
 *           is the correlation start: a host with an open HTTP service becomes a
 *           page the browser reads.
 * It never scans a NEW host (authorization is per-host and only the caller's
 * `host` is authorized), never mutates, never follows a target the caller didn't
 * own. Anything it can't safely run returns null (the recommendation stands).
 */
export async function capabilityDispatch(probe: NextProbe, ctx: ProbeContext): Promise<CognitiveClaim | null> {
  const { input, missionId, now } = ctx
  if (probe.sense === 'repo' && input.repoPath && /vet|dependenc|transitive|lockfile|supply/i.test(probe.description)) {
    const brief = await scout(input.repoPath, { checkDeps: (input.checkDeps ?? 0) + 10, wrapScanners: input.wrapScanners })
    return repoBriefToClaim(brief, missionId, now)
  }
  if (probe.sense === 'web') {
    // Explicit URL always allowed; else derive from the REAL HTTP ports the net
    // sense discovered (Kimi A4) — not a blind https://host/. Only for the host the
    // caller authorized, and only once.
    const url = input.url ?? deriveWebTarget(ctx.mission, input)
    const already = ctx.mission.allClaims().some((c) => c.sense === 'web' && c.operation === 'observe')
    if (url && !already) {
      const brief = await observe(url)
      return browserBriefToClaim(brief, missionId, now)
    }
  }
  return null
}

/** Pick a web URL to observe from the host's discovered HTTP ports. Prefers a real
 *  open HTTP(S) port the net sense already found (e.g. :3000, :8080) over a blind
 *  guess; only for an authorized host. Falls back to https://host/ if net saw no
 *  obvious web port. Never targets a host other than the one the caller owns. */
function deriveWebTarget(mission: MissionGraph, input: MissionInput): string | null {
  if (!input.host || !input.authorized) return null
  const HTTP_PORTS = new Set([80, 443, 8080, 8443, 3000, 8000, 5000, 8888])
  const found: Array<{ port: number; tls: boolean }> = []
  for (const e of mission.entities()) {
    if (e.kind !== 'port') continue
    const m = /^net:port:.+:(\d+)$/.exec(e.id)
    if (!m) continue
    const port = Number(m[1])
    const label = (e.label ?? '').toLowerCase()
    if (!(HTTP_PORTS.has(port) || /http/.test(label))) continue
    found.push({ port, tls: port === 443 || port === 8443 || /https|tls|ssl/.test(label) })
  }
  if (!found.length) return `https://${input.host}/`
  found.sort((a, b) => Number(b.tls) - Number(a.tls) || a.port - b.port)
  const best = found[0]
  const scheme = best.tls ? 'https' : 'http'
  const bare = (scheme === 'http' && best.port === 80) || (scheme === 'https' && best.port === 443)
  return `${scheme}://${input.host}${bare ? '' : `:${best.port}`}/`
}

/**
 * The one universal Voyager: a THIN orchestrator over modular senses. It does not
 * absorb the senses — it composes them. It decomposes intent (via a swappable
 * brain), invokes the real published senses (voyager-net, voyager-repo,
 * voyager-browser) in parallel, adapts their output into CognitiveClaims, runs a
 * live MissionGraph, and synthesizes a conclusion. Sensing is autonomous; acting
 * stays consent-gated (the claims carry the withheld actions — never applied here).
 */
export async function runMission(intent: string, input: MissionInput, now: number): Promise<MissionRun> {
  const log = input.onLog ?? (() => {})
  const brain: Brain = input.brain ?? new DeterministicBrain()
  const cg = new CapabilityGraph()
  seedFamilyCapabilities(cg)

  const mission = new MissionGraph('m', intent, `resolve: ${intent}`)
  const goals = brain.decomposeAsync ? await brain.decomposeAsync(intent, mission.id) : brain.decompose(intent, mission.id)
  for (const g of goals) mission.addGoal(g)
  // Link claims to the ACTUAL goals the brain returned (not hardcoded ids that
  // only the DeterministicBrain guarantees). First goal = observe, last = conclude.
  const observeGoalId = goals[0]?.id
  const concludeGoalId = goals[goals.length - 1]?.id

  // ── Observe: fan out across the real senses AND every target, resilient
  // (allSettled semantics). Multi-target: singular + plural fields are merged and
  // de-duplicated, so N repos / N hosts / N URLs are all observed into ONE mission.
  const uniq = (xs: Array<string | undefined>): string[] => [...new Set(xs.filter((x): x is string => !!x))]
  const repoPaths = uniq([input.repoPath, ...(input.repoPaths ?? [])])
  const hosts = uniq([input.host, ...(input.hosts ?? [])])
  const urls = uniq([input.url, ...(input.urls ?? [])])

  const jobs: Array<Promise<{ claim: CognitiveClaim; capability: string }>> = []
  for (const repoPath of repoPaths) {
    jobs.push(
      senseJob('repo', 'repo.scout', async () => repoBriefToClaim(await scout(repoPath, { checkDeps: input.checkDeps, wrapScanners: input.wrapScanners }), mission.id, now, observeGoalId), now, mission.id, observeGoalId).then((claim) => {
        log(`repo sense: oriented in ${repoPath}`)
        return { claim, capability: 'repo.scout' }
      }),
    )
  }
  for (const host of hosts) {
    jobs.push(
      senseJob('net', 'net.scan', async () => netBriefToClaim(await scan(host, { authorized: input.authorized, ports: input.ports, timeoutMs: input.timeoutMs }), mission.id, now, observeGoalId), now, mission.id, observeGoalId).then((claim) => {
        log(`net sense: audited ${host}`)
        return { claim, capability: 'net.scan' }
      }),
    )
  }
  for (const url of urls) {
    jobs.push(
      senseJob('web', 'browser.observe', async () => browserBriefToClaim(await observe(url), mission.id, now, observeGoalId), now, mission.id, observeGoalId).then((claim) => {
        log(`browser sense: observed ${url}`)
        return { claim, capability: 'browser.observe' }
      }),
    )
  }

  const settled = await Promise.allSettled(jobs)
  for (const s of settled) {
    if (s.status !== 'fulfilled') continue // unreachable (jobs never reject), but safe
    const { claim, capability } = s.value
    mission.addClaim(claim)
    cg.recordOutcome(capability, claim.confidence >= USABLE_OBSERVATION_CONFIDENCE)
  }
  // Goal statuses are set at the end from ACTUAL evidence coverage — not
  // prematurely satisfied here (that was the P0: a mission looked done before we
  // knew whether every required sense delivered).

  // ── Iterate: the LIVE loop. Pick the most informative next probe, execute it,
  // re-plan — bounded, and only while a probe is actually dispatchable. This is
  // what makes it re-plan instead of a one-shot fan-out. `pickNext` is no longer
  // dead code. Acting is still consent-gated: the default dispatch only re-reads.
  const dispatch = input.dispatch ?? ((probe, ctx) => capabilityDispatch(probe, ctx))
  const maxRounds = Math.max(0, input.maxRounds ?? 2)
  // A non-dispatchable probe must NOT kill the whole loop — it just gets skipped so
  // the next-best candidate still gets its turn (Kimi A1). We track what we've
  // tried so the loop always makes progress and terminates when nothing new remains.
  const tried = new Set<string>()
  const probeKey = (p: NextProbe): string => `${p.sense}|${p.capability ?? ''}|${p.description}`
  let round = 0
  while (round < maxRounds) {
    const state = mission.state()
    const candidates = dedupeProbes(mission.allClaims().flatMap((c) => c.suggestedNextProbes)).filter((p) => !tried.has(probeKey(p)))
    // The model ROUTES when it can: it chooses among the fresh candidates by learned
    // capability utility. A rule-based brain uses the planner's bestNextProbe.
    const probe = brain.pickNextAsync ? await brain.pickNextAsync(state, cg, candidates) : brain.pickNext(state)
    if (!probe || tried.has(probeKey(probe))) break // nothing new left to try → done
    tried.add(probeKey(probe))
    mission.markProbeExecuted(probe)
    round++
    log(`probe (round ${round}): [${probe.sense}] ${probe.description}`)
    let claim: CognitiveClaim | null = null
    try {
      claim = await dispatch(probe, { intent, input, missionId: mission.id, now, mission })
    } catch {
      claim = null
    }
    if (!claim) continue // not dispatchable RIGHT NOW → skip it, keep exploring the rest
    mission.addClaim(claim)
    cg.recordOutcome(`${probe.sense}.probe`, claim.confidence >= USABLE_OBSERVATION_CONFIDENCE)
  }

  // ── Correlate: link the senses' entities into cross-sense cause→effect edges so
  // the mission has a real causal chain + rootCause, not just an aggregation.
  const correlation = correlate(mission.allClaims(), mission.id, now, concludeGoalId)
  if (correlation) {
    mission.addClaim(correlation)
    log(`correlate: ${correlation.causalChain.length} cross-sense edge(s) (web ↔ repo ↔ net)`)
  }

  // ── Infer: the brain fuses the observations into one conclusion ─────────────
  log('brain: synthesizing…')
  const conclusion = brain.synthesizeAsync
    ? await brain.synthesizeAsync(intent, mission.id, mission.allClaims(), now)
    : brain.synthesize(intent, mission.id, mission.allClaims(), now)
  mission.addClaim(conclusion)

  // ── Verify: record that the mission produced a usable conclusion, and close
  // every goal — so mission.state().satisfied means something (not always false).
  // ── Truthful verification (P0): a mission is only VERIFIED when EVERY sense it
  // was asked to use produced a usable observation. Partial coverage → the mission
  // is honestly PARTIAL (not satisfied); a required sense that failed → the
  // conclusion says so instead of quietly declaring success. This is what stops a
  // repo+host mission from reading "satisfied" when the host scan was refused.
  const requestedSenses: CognitiveClaim['sense'][] = []
  if (repoPaths.length) requestedSenses.push('repo')
  if (hosts.length) requestedSenses.push('net')
  if (urls.length) requestedSenses.push('web')
  const usableSenses = new Set(
    mission.allClaims().filter((c) => c.operation === 'observe' && c.confidence >= USABLE_OBSERVATION_CONFIDENCE).map((c) => c.sense),
  )
  const delivered = requestedSenses.filter((s) => usableSenses.has(s))
  const missing = requestedSenses.filter((s) => !usableSenses.has(s))
  const fullCoverage = requestedSenses.length > 0 && missing.length === 0
  const partialCoverage = delivered.length > 0 && missing.length > 0
  const method = requestedSenses.length
    ? `required-sense coverage ${delivered.length}/${requestedSenses.length}${missing.length ? ` — missing: ${missing.join(', ')}` : ''}`
    : 'no sense requested — nothing to verify'
  mission.addClaim(
    newClaim(
      {
        missionId: mission.id, goalId: concludeGoalId, sense: 'memory', operation: 'verify',
        verdict: fullCoverage
          ? `verified on the full requested evidence (${delivered.join(' + ')})`
          : partialCoverage
            ? `PARTIAL — concluded on ${delivered.join(' + ')} only; ${missing.join(', ')} produced no usable evidence`
            : requestedSenses.length
              ? `NOT verified — no requested sense produced usable evidence (${missing.join(', ')})`
              : 'not verified — the mission requested no sense to observe',
        confidence: fullCoverage ? 0.8 : partialCoverage ? 0.4 : 0.2,
        unknowns: missing.map((s) => `${s}: required sense produced no usable observation — coverage incomplete`),
        verification: { passed: fullCoverage, method },
      },
      now,
    ),
  )
  // Close goals from ACTUAL coverage: satisfied only on full coverage; partial when
  // some (or no) senses were asked but not all delivered; failed when a requested
  // sense delivered nothing at all. mission.state().satisfied requires EVERY goal
  // satisfied, so partial/failed correctly keep the mission un-satisfied.
  const goalStatus = fullCoverage ? 'satisfied' : partialCoverage || requestedSenses.length === 0 ? 'partial' : 'failed'
  for (const g of goals) mission.setGoalStatus(g.id, goalStatus)
  if (goalStatus !== 'satisfied') log(`verification: mission ${goalStatus} — ${method}`)
  // ── Propose remediation (the HANDS): remediable findings → consent-gated `act`
  // claims, always WITHHELD. The agent never applies — it plans a reversible fix
  // and hands the mission a pendingAction. Sensing autonomous; acting gated.
  if (input.remediate !== false) {
    const acts = await proposeRemediations(mission.allClaims(), now)
    for (const a of acts) mission.addClaim(a)
    if (acts.length) log(`hands: proposed ${acts.length} reversible remediation(s) — all WITHHELD pending consent`)
  }

  // ── Drift: compare this audit to the last one over the same targets, then persist
  // the new baseline. Turns a one-shot snapshot into a tracked timeline (NEW /
  // RESOLVED / unchanged) — memory across missions, opt-in via baselineDir.
  if (input.baselineDir) {
    const key = missionKey({ repoPaths, hosts, urls })
    const diff = await diffBaseline(input.baselineDir, key, mission, input.baselineKey)
    mission.addClaim(driftClaim(diff, mission.id, now, concludeGoalId))
    await saveBaseline(input.baselineDir, key, mission, now, input.baselineKey)
    if (!diff.first) log(`drift: ${diff.added.length} new, ${diff.resolved.length} resolved since last audit`)
  }

  return { capabilities: cg, mission }
}
