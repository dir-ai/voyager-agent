import type { CognitiveClaim, Goal, MissionState, NextProbe } from '@dir-ai/voyager-contract'
import { newClaim } from '@dir-ai/voyager-contract'

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
    // are minted at very low confidence (≈0.2); a healthy observation still
    // carries `unknowns` (e.g. consent-withheld actions) and must NOT be discarded.
    const observations = claims.filter((c) => c.operation === 'observe' && c.confidence >= 0.4)
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
