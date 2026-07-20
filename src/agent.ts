import { CapabilityGraph, MissionGraph, newClaim, seedFamilyCapabilities, type CognitiveClaim, type NextProbe } from '@dir-ai/voyager-contract'
import { scan } from '@dir-ai/voyager-net'
import { scout } from '@dir-ai/voyager-repo'
import { observe } from '@dir-ai/voyager-browser'
import { browserBriefToClaim, netBriefToClaim, repoBriefToClaim } from './adapters.js'
import { proposeRemediations } from './remediation.js'
import { DeterministicBrain, dedupeProbes, type Brain } from './brain.js'
import { ERROR_CLAIM_CONFIDENCE, USABLE_OBSERVATION_CONFIDENCE } from './constants.js'

export interface MissionInput {
  /** A local repo path to orient in (via voyager-repo). */
  repoPath?: string
  /** A host/domain you own to audit (via voyager-net). */
  host?: string
  /** A live URL to observe (via voyager-browser). */
  url?: string
  /** REQUIRED to actually scan the host (voyager-net's fail-closed gate). */
  authorized?: boolean
  /** Verify up to N dependencies via Voyager during the repo scout. */
  checkDeps?: number
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

/** The safe default probe executor: the ONLY thing the agent will re-run on its
 *  own is a deeper, read-only pass — deepening repo dependency-vetting when a
 *  probe asks for it. Everything else returns null (stop) unless the caller
 *  injects a richer `dispatch`. It never acts, never scans a new host (that needs
 *  authorization), never fetches a new URL without intent. */
async function defaultDispatch(probe: NextProbe, ctx: ProbeContext): Promise<CognitiveClaim | null> {
  if (probe.sense === 'repo' && ctx.input.repoPath && /vet|dependenc/i.test(probe.description)) {
    const deeper = (ctx.input.checkDeps ?? 0) + 10
    const brief = await scout(ctx.input.repoPath, { checkDeps: deeper })
    return repoBriefToClaim(brief, ctx.missionId, ctx.now)
  }
  return null
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

  // ── Observe: fan out across the real senses, resilient (allSettled semantics) ──
  const jobs: Array<Promise<{ claim: CognitiveClaim; capability: string }>> = []
  if (input.repoPath) {
    jobs.push(
      senseJob('repo', 'repo.scout', async () => repoBriefToClaim(await scout(input.repoPath!, { checkDeps: input.checkDeps }), mission.id, now, observeGoalId), now, mission.id, observeGoalId).then((claim) => {
        log(`repo sense: oriented in ${input.repoPath}`)
        return { claim, capability: 'repo.scout' }
      }),
    )
  }
  if (input.host) {
    jobs.push(
      senseJob('net', 'net.scan', async () => netBriefToClaim(await scan(input.host!, { authorized: input.authorized }), mission.id, now, observeGoalId), now, mission.id, observeGoalId).then((claim) => {
        log(`net sense: audited ${input.host}`)
        return { claim, capability: 'net.scan' }
      }),
    )
  }
  if (input.url) {
    jobs.push(
      senseJob('web', 'browser.observe', async () => browserBriefToClaim(await observe(input.url!), mission.id, now, observeGoalId), now, mission.id, observeGoalId).then((claim) => {
        log(`browser sense: observed ${input.url}`)
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
  if (observeGoalId) mission.setGoalStatus(observeGoalId, 'satisfied')

  // ── Iterate: the LIVE loop. Pick the most informative next probe, execute it,
  // re-plan — bounded, and only while a probe is actually dispatchable. This is
  // what makes it re-plan instead of a one-shot fan-out. `pickNext` is no longer
  // dead code. Acting is still consent-gated: the default dispatch only re-reads.
  const dispatch = input.dispatch ?? ((probe, ctx) => defaultDispatch(probe, ctx))
  const maxRounds = Math.max(0, input.maxRounds ?? 2)
  for (let round = 0; round < maxRounds; round++) {
    // The model ROUTES when it can: pool every candidate probe the senses
    // suggested and let pickNextAsync choose by learned capability utility.
    // A rule-based brain (no pickNextAsync) still uses the planner's bestNextProbe.
    const state = mission.state()
    const probe = brain.pickNextAsync
      ? await brain.pickNextAsync(state, cg, dedupeProbes(mission.allClaims().flatMap((c) => c.suggestedNextProbes)))
      : brain.pickNext(state)
    if (!probe) break
    // Mark it executed in the mission graph itself, so the planner (bestNextProbe)
    // never re-proposes it — the loop can't spin on the same probe.
    mission.markProbeExecuted(probe)
    log(`probe (round ${round + 1}): [${probe.sense}] ${probe.description}`)
    let claim: CognitiveClaim | null = null
    try {
      claim = await dispatch(probe, { intent, input, missionId: mission.id, now })
    } catch {
      claim = null
    }
    if (!claim) break // not dispatchable → stop iterating (recommendation stands)
    mission.addClaim(claim)
    cg.recordOutcome(`${probe.sense}.probe`, claim.confidence >= USABLE_OBSERVATION_CONFIDENCE)
  }

  // ── Infer: the brain fuses the observations into one conclusion ─────────────
  log('brain: synthesizing…')
  const conclusion = brain.synthesizeAsync
    ? await brain.synthesizeAsync(intent, mission.id, mission.allClaims(), now)
    : brain.synthesize(intent, mission.id, mission.allClaims(), now)
  mission.addClaim(conclusion)

  // ── Verify: record that the mission produced a usable conclusion, and close
  // every goal — so mission.state().satisfied means something (not always false).
  const usable = mission.allClaims().some((c) => c.operation === 'observe' && c.confidence >= USABLE_OBSERVATION_CONFIDENCE)
  mission.addClaim(
    newClaim({ missionId: mission.id, goalId: concludeGoalId, sense: 'memory', operation: 'verify', verdict: usable ? 'mission reached a conclusion from usable observations' : 'mission concluded but observations were insufficient', confidence: usable ? 0.8 : 0.3, verification: { passed: usable, method: 'usable-observation check' } }, now),
  )
  // Every goal is now accounted for: observed, synthesized, verified. Close them
  // so mission.state().satisfied reflects a real conclusion (the iterative-loop
  // refactor left only the observe goal closed).
  for (const g of goals) mission.setGoalStatus(g.id, 'satisfied')
  // ── Propose remediation (the HANDS): remediable findings → consent-gated `act`
  // claims, always WITHHELD. The agent never applies — it plans a reversible fix
  // and hands the mission a pendingAction. Sensing autonomous; acting gated.
  if (input.remediate !== false) {
    const acts = await proposeRemediations(mission.allClaims(), now)
    for (const a of acts) mission.addClaim(a)
    if (acts.length) log(`hands: proposed ${acts.length} reversible remediation(s) — all WITHHELD pending consent`)
  }

  return { capabilities: cg, mission }
}
