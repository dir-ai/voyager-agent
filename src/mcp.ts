#!/usr/bin/env node
/**
 * voyager-agent MCP server (stdio). One tool: run_mission — describe a goal and
 * Voyager activates the senses it needs (repo, net), runs a live mission through
 * the cognitive contract, and returns the CognitiveClaims + mission state.
 *
 * The calling host is the reasoning brain: this server uses a built-in
 * deterministic brain to structure the mission and hands back the full claim
 * graph so the host can reason further. Sensing is autonomous; the host's own
 * net audit stays FAIL-CLOSED (authorized:true required). No action is applied.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { runMission } from './agent.js'
import { VERSION } from './version.js'

const server = new Server({ name: 'voyager-agent', version: VERSION }, { capabilities: { tools: {} } })

const TOOLS = [
  {
    name: 'run_mission',
    description:
      "The one universal Voyager. Give a goal in plain language; Voyager activates the senses it needs and runs a live mission, returning a graph of CognitiveClaims (observe/infer), the entities/relationships/contradictions found across senses, and the single most informative next probe. Provide `repoPath` to orient in a local repository (voyager-repo) and/or `host`+`authorized:true` to audit ONE host you own (voyager-net, FAIL-CLOSED). Sensing is read-only and autonomous; any remediation stays consent-gated and is NEVER applied here. isError:true means the mission could not run, not that the systems are clean.",
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        intent: { type: 'string', minLength: 1, maxLength: 400, description: 'The goal, in plain language.' },
        repoPath: { type: 'string', maxLength: 1024, description: 'A local repository path to orient in.' },
        host: { type: 'string', maxLength: 253, description: 'A single host/domain you own, to audit.' },
        authorized: { type: 'boolean', description: 'Assert you own/are permitted to test `host`. Required to audit it.' },
        checkDeps: { type: 'integer', minimum: 0, maximum: 50, description: 'Verify up to N dependencies during the repo scout.' },
      },
      required: ['intent'],
    },
  },
] as const

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }))

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params
  const a = args as Record<string, unknown>
  const ok = (data: unknown, isError = false) => ({ content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }], ...(isError ? { isError: true } : {}) })
  const err = (message: string) => ok({ error: message }, true)

  try {
    if (name === 'run_mission') {
      const intent = typeof a.intent === 'string' ? a.intent.slice(0, 400) : ''
      if (!intent) return err('intent required')
      const { mission } = await runMission(
        intent,
        {
          repoPath: typeof a.repoPath === 'string' ? a.repoPath : undefined,
          host: typeof a.host === 'string' ? a.host : undefined,
          authorized: a.authorized === true,
          checkDeps: typeof a.checkDeps === 'number' && Number.isInteger(a.checkDeps) ? a.checkDeps : 0,
        },
        // No hidden clock in the pure library, but the server is a live process.
        Date.now(),
      )
      const claims = mission.allClaims()
      const senseErrored = claims.some((c) => c.operation === 'observe' && c.confidence < 0.4)
      return ok({ intent: mission.intent, claims, state: mission.state(), memory: mission.memoryHarvest() }, senseErrored)
    }
    return err(`Unknown tool: ${name}`)
  } catch (e) {
    return err(e instanceof Error ? e.message : String(e))
  }
})

export async function startMcpServer(): Promise<void> {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error(`voyager-agent MCP server v${VERSION} ready (stdio)`)
}

import { fileURLToPath } from 'node:url'
import { realpathSync } from 'node:fs'
function isDirectEntry(): boolean {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const self = fileURLToPath(import.meta.url)
  try {
    return realpathSync(self) === realpathSync(argv1)
  } catch {
    return self === argv1
  }
}
if (isDirectEntry()) {
  startMcpServer().catch((e) => {
    console.error(e instanceof Error ? e.stack : String(e))
    process.exit(1)
  })
}
