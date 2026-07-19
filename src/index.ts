// @dir-ai/voyager-agent — the one universal Voyager.
//
// A THIN, model-independent orchestrator over the modular sense-organs. It
// composes them (voyager-net, voyager-repo, … and the cognitive contract) into a
// single agent that decomposes intent, invokes the real senses, links their
// output into a live mission, and concludes — WITHOUT absorbing them into a
// monolith and WITHOUT acting on production autonomously. The reasoning model is
// injected (Brain) and swappable.
export { runMission, type MissionInput, type MissionRun } from './agent.js'
export { type Brain, DeterministicBrain } from './brain.js'
export { netBriefToClaim, repoBriefToClaim } from './adapters.js'
export { VERSION } from './version.js'
