#!/usr/bin/env node
/**
 * voyager-agent CLI — one entry. Describe the goal; Voyager activates the right
 * senses, runs a live mission, and concludes.
 */
import { runMission } from './agent.js'
import { VERSION } from './version.js'

function parseArgs(argv: string[]): { flags: Record<string, string | boolean>; positionals: string[] } {
  const boolean = new Set(['json', 'authorized'])
  const flags: Record<string, string | boolean> = {}
  const positionals: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const key = a.slice(2)
      const next = argv[i + 1]
      if (!boolean.has(key) && next !== undefined && !next.startsWith('--')) { flags[key] = next; i++ }
      else flags[key] = true
    } else positionals.push(a)
  }
  return { flags, positionals }
}

const OP: Record<string, string> = { observe: '👁 observe', infer: '🧠 infer', simulate: '🔮 simulate', act: '✋ act', verify: '✅ verify', learn: '📚 learn' }

const HELP = `voyager-agent v${VERSION} — one universal Voyager, one entry

USAGE
  voyager-agent mission "<goal>" [--repo <path>] [--host <domain> --authorized]
                                 [--check-deps N] [--json]
        Describe the goal; Voyager activates the senses it needs (repo, net),
        runs a live mission through the cognitive contract, and concludes.
        --authorized is required to audit a host (voyager-net is fail-closed).

  voyager-agent mcp
        Run as an MCP server (stdio) exposing one tool: run_mission.

  voyager-agent help | --version

The senses stay modular; the model that reasons is swappable. Sensing is
autonomous; any action stays consent-gated (never applied here).`

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2)
  const { flags, positionals } = parseArgs(rest)
  const json = flags.json === true

  if (cmd === 'mcp') {
    const { startMcpServer } = await import('./mcp.js')
    await startMcpServer()
    return new Promise<number>(() => {}) // stdio server runs until the transport closes
  }

  if (cmd !== 'mission') {
    if (cmd === '--version' || cmd === 'version') console.log(VERSION)
    else console.log(HELP)
    return 0
  }

  const intent = positionals[0]
  if (!intent) { console.error('mission needs a goal in quotes.'); return 2 }
  const { mission, capabilities } = await runMission(
    intent,
    {
      repoPath: typeof flags.repo === 'string' ? flags.repo : undefined,
      host: typeof flags.host === 'string' ? flags.host : undefined,
      authorized: flags.authorized === true,
      checkDeps: typeof flags['check-deps'] === 'string' ? Number(flags['check-deps']) || 0 : 0,
      onLog: (l) => { if (!json) console.error(`  · ${l}`) },
    },
    Date.now(),
  )

  if (json) {
    console.log(JSON.stringify({ intent: mission.intent, claims: mission.allClaims(), state: mission.state() }, null, 2))
    return 0
  }

  console.log(`\n\x1b[1mVoyager\x1b[0m — one agent, one entry.`)
  console.log(`\x1b[2mgoal:\x1b[0m "${mission.intent}"\n`)
  for (const c of mission.allClaims()) {
    console.log(`  ${OP[c.operation] ?? c.operation}  \x1b[2m[${c.sense}]\x1b[0m  \x1b[2m(${Math.round(c.confidence * 100)}% · ${c.strength})\x1b[0m`)
    console.log(`     ${c.verdict}`)
    for (const e of c.evidence.slice(0, 3)) console.log(`     \x1b[2m↳ ${e.what}${e.at ? `  (${e.at})` : ''}\x1b[0m`)
  }
  const s = mission.state()
  if (s.contradictions.length) for (const x of s.contradictions) console.log(`\n\x1b[33mcontradiction:\x1b[0m ${x.note}`)
  if (s.bestNextProbe) console.log(`\n\x1b[1mnext probe:\x1b[0m [${s.bestNextProbe.sense}] ${s.bestNextProbe.description}`)
  const mem = mission.memoryHarvest()
  if (mem.length) { console.log(`\n\x1b[1mlearned:\x1b[0m`); for (const m of mem.slice(0, 6)) console.log(`  · [${m.kind}] ${m.statement}`) }
  console.log(`\n\x1b[2mcapabilities used: ${capabilities.all().filter((c) => c.runs > 0).map((c) => c.id).join(', ') || '(none live)'}\x1b[0m\n`)
  return 0
}

main()
  .then((code) => process.exit(code))
  .catch((err) => { console.error(err instanceof Error ? (err.stack ?? err.message) : String(err)); process.exit(2) })
