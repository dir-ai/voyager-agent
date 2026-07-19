import { CapabilityGraph, MissionGraph, seedFamilyCapabilities } from '@dir-ai/voyager-contract'
import { scan } from '@dir-ai/voyager-net'
import { scout } from '@dir-ai/voyager-repo'
import { netBriefToClaim, repoBriefToClaim } from './adapters.js'
import { DeterministicBrain, type Brain } from './brain.js'

export interface MissionInput {
  /** A local repo path to orient in (via voyager-repo). */
  repoPath?: string
  /** A host/domain you own to audit (via voyager-net). */
  host?: string
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

/**
 * The one universal Voyager: a THIN orchestrator over modular senses. It does not
 * absorb the senses — it composes them. It decomposes intent (via a swappable
 * brain), invokes the real published senses (voyager-net, voyager-repo), adapts
 * their output into CognitiveClaims, runs a live MissionGraph, and synthesizes a
 * conclusion. Sensing is autonomous; acting stays consent-gated (the claims carry
 * the withheld actions — this orchestrator never applies them).
 */
export async function runMission(intent: string, input: MissionInput, now: number): Promise<MissionRun> {
  const log = input.onLog ?? (() => {})
  const brain = input.brain ?? new DeterministicBrain()
  const cg = new CapabilityGraph()
  seedFamilyCapabilities(cg)

  const mission = new MissionGraph('m', intent, `resolve: ${intent}`)
  for (const g of brain.decompose(intent, mission.id)) mission.addGoal(g)

  // ── Observe: fan out across the real senses the mission needs, in parallel ──
  const jobs: Array<Promise<void>> = []
  if (input.repoPath) {
    jobs.push((async () => {
      log(`repo sense: orienting in ${input.repoPath}…`)
      const brief = await scout(input.repoPath!, { checkDeps: input.checkDeps })
      mission.addClaim(repoBriefToClaim(brief, mission.id, now, 'g.observe'))
      cg.recordOutcome('repo.scout', !brief.error)
    })())
  }
  if (input.host) {
    jobs.push((async () => {
      log(`net sense: auditing ${input.host}…`)
      const brief = await scan(input.host!, { authorized: input.authorized })
      mission.addClaim(netBriefToClaim(brief, mission.id, now, 'g.observe'))
      cg.recordOutcome('net.scan', !brief.error)
    })())
  }
  await Promise.all(jobs)
  mission.setGoalStatus('g.observe', 'satisfied')

  // ── Infer: the brain fuses the observations into one conclusion ─────────────
  log('brain: synthesizing…')
  mission.addClaim(brain.synthesize(intent, mission.id, mission.allClaims(), now))
  mission.setGoalStatus('g.assess', 'satisfied')
  mission.setGoalStatus('g.conclude', 'satisfied')

  return { capabilities: cg, mission }
}
