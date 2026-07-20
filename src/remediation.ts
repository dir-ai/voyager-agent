import { newClaim, type CognitiveClaim } from '@dir-ai/voyager-contract'
import { plan, buildAction, preview, blastToTier, requiresHuman } from '@dir-ai/voyager-hands'

// Finding kinds the hands' catalog can remediate (DNS hygiene, the first slice).
const REMEDIABLE = new Set(['missing-dmarc', 'missing-caa', 'missing-spf'])

/**
 * The HANDS wired into the agent: turn remediable observations into PROPOSED,
 * REVERSIBLE `act` claims — always WITHHELD. The agent never applies anything; it
 * plans a consent-gated remediation and hands the mission a `pendingAction`. This
 * is where sensing (autonomous) meets acting (consent-gated) — the two never blur:
 * an act claim here carries the declarative action + its inverse, but status stays
 * 'withheld' until a human/policy consents through @dir-ai/voyager-hands.apply().
 */
export async function proposeRemediations(claims: readonly CognitiveClaim[], now: number): Promise<CognitiveClaim[]> {
  const out: CognitiveClaim[] = []
  const seen = new Set<string>()
  for (const c of claims) {
    if (c.operation !== 'observe' || c.confidence < 0.4) continue
    for (const e of c.evidence) {
      const kind = /\]\s*([a-z0-9-]+)\s*:/i.exec(e.what)?.[1]?.toLowerCase()
      const target = e.at
      if (!kind || !REMEDIABLE.has(kind) || !target) continue
      const dedupe = `${kind}|${target}`
      if (seen.has(dedupe)) continue
      seen.add(dedupe)

      const [proposal] = plan({ kind, target })
      if (!proposal) continue
      try {
        const action = proposal.ready ? buildAction(proposal.kind, proposal.target, proposal.params) : null
        const tier = action ? blastToTier(action.blastClass) : 'human-required'
        // A ready+reversible action is fully specified but WITHHELD; a not-ready one
        // (SPF/CAA the hands won't guess) is 'proposed' pending operator input.
        out.push(
          newClaim(
            {
              missionId: c.missionId, goalId: c.goalId, sense: 'memory', operation: 'act', capability: 'hands.dns',
              verdict: action ? `reversible remediation ready for ${kind} on ${target} (WITHHELD — needs consent): ${action.summary}` : `remediation for ${kind} on ${target} needs operator input: ${proposal.note}`,
              confidence: 0.6,
              actionResult: action
                ? { status: 'withheld', summary: action.summary, plan: action.summary, rollback: action.inverse?.summary, reversible: action.reversible, blastClass: action.blastClass, requiresConsent: requiresHuman(tier), withheldReason: 'the hands never apply autonomously — apply via @dir-ai/voyager-hands with an injected provider + explicit consent' }
                : { status: 'proposed', summary: proposal.note, reversible: true, blastClass: 'B0', requiresConsent: true, withheldReason: proposal.note },
              suggestedNextProbes: [{ sense: 'memory', capability: 'hands.dns', description: `consent + apply the ${kind} fix on ${target} via voyager-hands`, expectedInformationGain: 0.3, cost: 5 }],
            },
            now,
          ),
        )
      } catch {
        /* a malformed finding just yields no proposal */
      }
    }
  }
  return out
}
