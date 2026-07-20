// @dir-ai/voyager-agent — the one universal Voyager.
//
// A THIN, model-independent orchestrator over the modular sense-organs. It
// composes them (voyager-net, voyager-repo, … and the cognitive contract) into a
// single agent that decomposes intent, invokes the real senses, links their
// output into a live mission, and concludes — WITHOUT absorbing them into a
// monolith and WITHOUT acting on production autonomously. The reasoning model is
// injected (Brain) and swappable.
export { runMission, capabilityDispatch, type MissionInput, type MissionRun, type ProbeContext } from './agent.js'
export { type Brain, DeterministicBrain, dedupeProbes } from './brain.js'
export { LlmBrain, type Complete, type ChatMessage, type LlmBrainOptions, extractJson } from './llm-brain.js'
export { ProgrexBrain, progrexComplete, type ProgrexBrainOptions, PROGREX_DEFAULT_MODEL } from './progrex.js'
export { netBriefToClaim, repoBriefToClaim, browserBriefToClaim } from './adapters.js'
export { proposeRemediations } from './remediation.js'
export { correlate } from './correlate.js'
export { diffBaseline, saveBaseline, driftClaim, fingerprints, missionKey, type BaselineDiff } from './baseline.js'
export { missionReport, type MissionReport } from './report.js'
export { complianceFor, controlTags, type Controls } from './compliance.js'
export { ERROR_CLAIM_CONFIDENCE, USABLE_OBSERVATION_CONFIDENCE } from './constants.js'
export { VERSION } from './version.js'
