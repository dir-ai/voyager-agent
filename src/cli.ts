#!/usr/bin/env node
/**
 * voyager-agent CLI — one entry. Describe the goal; Voyager activates the right
 * senses, runs a live mission, and concludes.
 */
import { runMission } from './agent.js'
import { VERSION } from './version.js'

/** Parse a --ports value: "80,443,6379", a range "1-1024", or "top1000". */
function parsePorts(spec: string): number[] | undefined {
  const s = spec.trim().toLowerCase()
  if (s === 'top1000') return Array.from({ length: 1000 }, (_, i) => i + 1)
  const out = new Set<number>()
  for (const part of s.split(',')) {
    const range = /^(\d+)-(\d+)$/.exec(part.trim())
    if (range) {
      const [a, b] = [Number(range[1]), Number(range[2])]
      for (let p = Math.max(1, a); p <= Math.min(65535, b); p++) out.add(p)
    } else {
      const p = Number(part.trim())
      if (Number.isInteger(p) && p > 0 && p < 65536) out.add(p)
    }
  }
  return out.size ? [...out] : undefined
}

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
                                 [--url <http-url>] [--check-deps N] [--json]
        Describe the goal; Voyager activates the senses it needs (repo, net,
        browser), runs a live mission through the cognitive contract, and
        concludes. --authorized is required to audit a host (fail-closed).

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
  // A value-flag given with no value (or immediately followed by another --flag)
  // parses as boolean true — warn instead of silently dropping the request.
  for (const k of ['repo', 'host', 'url']) {
    if (flags[k] === true) { console.error(`\x1b[33mwarning:\x1b[0m --${k} needs a value (e.g. --${k} <value>) — ignoring it`); }
  }
  const checkDepsRaw = typeof flags['check-deps'] === 'string' ? Number(flags['check-deps']) || 0 : 0
  const ports = typeof flags.ports === 'string' ? parsePorts(flags.ports) : undefined
  const maxRoundsRaw = typeof flags['max-rounds'] === 'string' ? Number(flags['max-rounds']) : NaN
  const timeoutRaw = typeof flags.timeout === 'string' ? Number(flags.timeout) : NaN
  const { mission, capabilities } = await runMission(
    intent,
    {
      repoPath: typeof flags.repo === 'string' ? flags.repo : undefined,
      host: typeof flags.host === 'string' ? flags.host : undefined,
      url: typeof flags.url === 'string' ? flags.url : undefined,
      authorized: flags.authorized === true,
      checkDeps: Math.min(50, Math.max(0, checkDepsRaw)), // cap matches the MCP schema
      ports, // open the net sense wider (Kimi A3): --ports "1-1000" or "80,443,6379"
      maxRounds: Number.isFinite(maxRoundsRaw) ? Math.min(10, Math.max(0, maxRoundsRaw)) : undefined,
      timeoutMs: Number.isFinite(timeoutRaw) ? Math.min(15_000, Math.max(500, timeoutRaw)) : undefined,
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
