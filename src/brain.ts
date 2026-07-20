import type { CapabilityGraph, CognitiveClaim, Goal, MissionState, NextProbe } from '@dir-ai/voyager-contract'
import { newClaim } from '@dir-ai/voyager-contract'
import { USABLE_OBSERVATION_CONFIDENCE } from './constants.js'

/**
 * The reasoning brain — the MODEL-INDEPENDENT seam. An LLM implements this
 * interface to decompose intent, choose the next probe, and synthesize a
 * conclusion. Swap the model without touching the senses, the memory, or the
 * mission machinery. The DeterministicBrain below is a rule-based stand-in so the
 * agent runs (and is testable) with NO model at all.
 */
export interface Brain {
  /** Turn a free-text intent into an ordered goal graph. */
  decompose(intent: string, missionId: string): Goal[]
  /** Pick the most useful next probe given the live mission state. */
  pickNext(state: MissionState): NextProbe | null
  /** Fuse the gathered claims into one conclusion (an `infer` claim). */
  synthesize(intent: string, missionId: string, claims: readonly CognitiveClaim[], now: number): CognitiveClaim
  /** Optional model-backed variants. When present, `runMission` prefers them;
   *  a brain that only reasons synchronously (e.g. DeterministicBrain) omits them. */
  decomposeAsync?(intent: string, missionId: string): Promise<Goal[]>
  synthesizeAsync?(intent: string, missionId: string, claims: readonly CognitiveClaim[], now: number): Promise<CognitiveClaim>
  /** Optional model + capability-aware routing. Given the live state, the
   *  CapabilityGraph (with LEARNED reliability/cost per organ), and the pooled
   *  candidate probes, the model chooses which capability to exercise next — so it
   *  routes among ALL the senses/hands by evidence, not by a fixed rule. When
   *  present, `runMission` prefers it over the sync `pickNext`. */
  pickNextAsync?(state: MissionState, capabilities: CapabilityGraph, candidates: readonly NextProbe[]): Promise<NextProbe | null>
}

/** De-duplicate probes by (sense, capability, description) — the pooled menu the
 *  router chooses from can contain the same suggestion emitted by several senses. */
export function dedupeProbes(probes: readonly NextProbe[]): NextProbe[] {
  const seen = new Set<string>()
  const out: NextProbe[] = []
  for (const p of probes) {
    if (!p) continue
    const key = `${p.sense}|${p.capability ?? ''}|${p.description}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(p)
  }
  return out
}

export class DeterministicBrain implements Brain {
  decompose(intent: string, missionId: string): Goal[] {
    // A generic understand → assess → conclude arc; a real LLM would tailor it.
    return [
      { id: 'g.observe', missionId, statement: `observe the systems referenced by: "${intent}"`, status: 'open', dependsOn: [] },
      { id: 'g.assess', missionId, statement: 'assess risks and correlate across senses', status: 'open', dependsOn: ['g.observe'] },
      { id: 'g.conclude', missionId, statement: 'conclude with a verdict, evidence and next steps', status: 'open', dependsOn: ['g.assess'] },
    ]
  }

  pickNext(state: MissionState): NextProbe | null {
    return state.bestNextProbe
  }

  synthesize(intent: string, missionId: string, claims: readonly CognitiveClaim[], now: number): CognitiveClaim {
    // A usable observation is any observe claim that isn't a sense error. Errors
    // are minted at very low confidence; a healthy observation still carries
    // `unknowns` (e.g. consent-withheld actions) and must NOT be discarded.
    const observations = claims.filter((c) => c.operation === 'observe' && c.confidence >= USABLE_OBSERVATION_CONFIDENCE)
    const sensesSeen = [...new Set(observations.map((c) => c.sense))]
    const allEvidence = observations.flatMap((c) => c.evidence)
    const highSignals = allEvidence.filter((e) => /\[(high|critical)\]/i.test(e.what))
    const confidence = observations.length ? Math.min(0.9, observations.reduce((s, c) => s + c.confidence, 0) / observations.length) : 0.3

    const verdict = observations.length
      ? `${sensesSeen.join(' + ')} observed; ${highSignals.length} high/critical signal(s). ${highSignals.length ? 'Attention required.' : 'No high-severity issue surfaced.'}`
      : `no usable observations for "${intent}" — a sense was unavailable or errored`

    return newClaim({
      missionId, goalId: 'g.conclude', sense: 'memory', operation: 'infer', verdict, confidence,
      evidence: highSignals.slice(0, 6),
      entities: dedupe(observations.flatMap((c) => c.entities)),
      relationships: observations.flatMap((c) => c.relationships),
      suggestedNextProbes: observations.flatMap((c) => c.suggestedNextProbes).slice(0, 4),
      unknowns: [...new Set(claims.flatMap((c) => c.unknowns))],
      memoryCandidates: observations.flatMap((c) => c.memoryCandidates),
    }, now)
  }
}

function dedupe<T extends { id: string }>(xs: T[]): T[] {
  const seen = new Set<string>()
  return xs.filter((x) => (seen.has(x.id) ? false : (seen.add(x.id), true)))
}
