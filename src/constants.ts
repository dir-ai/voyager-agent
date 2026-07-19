/**
 * The single source of truth for the "usable observation" partition. A sense
 * ERROR is minted below ERROR_CLAIM_CONFIDENCE; a healthy observation sits at or
 * above USABLE_OBSERVATION_CONFIDENCE. synthesize() fuses only usable claims, and
 * the MCP layer flags a failed mission by the same line — so the threshold must
 * live in ONE place, not be duplicated as a magic number across files.
 *
 * Invariant (guarded by a test): ERROR_CLAIM_CONFIDENCE < USABLE_OBSERVATION_CONFIDENCE
 * ≤ every healthy-observation confidence floor in the adapters.
 */
export const ERROR_CLAIM_CONFIDENCE = 0.2
export const USABLE_OBSERVATION_CONFIDENCE = 0.4
