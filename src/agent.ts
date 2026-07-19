import { CapabilityGraph, MissionGraph, newClaim, seedFamilyCapabilities, type CognitiveClaim } from '@dir-ai/voyager-contract'
import { scan } from '@dir-ai/voyager-net'
import { scout } from '@dir-ai/voyager-repo'
import { observe } from '@dir-ai/voyager-browser'
import { browserBriefToClaim, netBriefToClaim, repoBriefToClaim } from './adapters.js'
import { DeterministicBrain, type Brain } from './brain.js'
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
  onLog?: (line: string) => void
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
  for (const g of goals) mission.setGoalStatus(g.id, 'satisfied')

  return { capabilities: cg, mission }
}
