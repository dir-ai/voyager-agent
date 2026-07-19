# @dir-ai/voyager-agent

**The one universal Voyager.** A thin, model-independent orchestrator that turns
the modular Voyager senses — `voyager-repo` (code), `voyager-net` (hosts), and
the cognitive contract that binds them — into a single agent. You name a goal;
Voyager activates the senses it needs, runs a **live mission**, links the
evidence into one graph, and concludes.

It is **composition, not a monolith.** The agent never absorbs the senses — it
calls the published organs and adapts what they see into the shared
[`CognitiveClaim`](https://www.npmjs.com/package/@dir-ai/voyager-contract)
substrate. The reasoning model is a **swappable seam** (`Brain`); a rule-based
brain ships so it runs with no LLM at all.

> **Sensing is autonomous. Acting is not.** Every sense here is read-only. Any
> remediation a mission surfaces is carried as a *consent-gated, withheld*
> action and is **never applied** by this orchestrator.

## Install

```bash
npm i -g @dir-ai/voyager-agent
```

## Use

```bash
# Orient in a repo and flag risk (voyager-repo)
voyager-agent mission "audit this project" --repo .

# Audit ONE host you own (voyager-net — fail-closed, needs --authorized)
voyager-agent mission "check my server's exposure" --host example.com --authorized

# Observe a live page (voyager-browser — read-only, static HTML)
voyager-agent mission "check my landing page" --url https://example.com

# All three senses in one mission; vet 10 dependencies; machine-readable
voyager-agent mission "full audit" --repo . --host example.com --authorized --url https://example.com --check-deps 10 --json
```

Senses fan out in parallel and are **resilient**: a sense that errors (or even
throws) becomes a low-confidence, flagged observation — it never crashes the
mission or discards a sibling sense's good result.

```
Voyager — one agent, one entry.
goal: "orient in this repo and flag risk"

  👁 observe  [repo]  (70% · moderate)
     @dir-ai/voyager-agent@0.1.0 — The one universal Voyager…
     ↳ [low] no-lockfile: no lockfile — installed versions are not pinned/reproducible
  🧠 infer  [memory]  (70% · moderate)
     repo observed; 0 high/critical signal(s). No high-severity issue surfaced.

next probe: [repo] open src/index.ts
```

## As an MCP server

One tool, `run_mission` — describe a goal, get back the full claim graph.

```bash
voyager-agent mcp            # stdio
```

```json
{
  "command": "voyager-agent",
  "args": ["mcp"]
}
```

## As a library

```ts
import { runMission, DeterministicBrain, type Brain } from '@dir-ai/voyager-agent'

const { mission } = await runMission(
  'audit this repo and my host',
  { repoPath: '.', host: 'example.com', authorized: true /* your own host */ },
  Date.now(),
)

for (const claim of mission.allClaims()) console.log(claim.operation, claim.sense, claim.verdict)
console.log(mission.state().bestNextProbe)   // the most informative next step
console.log(mission.state().contradictions)  // where two senses disagree
```

### Bring your own model

The `Brain` interface is the whole point — it's where an LLM plugs in without
touching the senses, the memory, or the mission machinery. A ready-made
`LlmBrain` ships: give it one **model-agnostic** `complete()` function and it
plans and synthesizes through the model. Wire Claude, a local server, or any
OpenAI-compatible endpoint — Voyager never depends on a specific SDK.

```ts
import { runMission, LlmBrain } from '@dir-ai/voyager-agent'

const brain = new LlmBrain({
  // Return the model's text for these messages — that's the whole dependency.
  async complete(messages) {
    const res = await myModel.chat(messages)   // Claude, local, OpenAI-compatible…
    return res.text
  },
})

await runMission('audit this repo and my host', { repoPath: '.', brain }, Date.now())
```

`LlmBrain` is **fail-safe**: if the model errors or returns unparseable output,
it degrades to the built-in rule-based brain for that step — a bad completion
can never take a mission down, only make it less clever once. You can also
implement the `Brain` interface directly for full control.

## How it works

```
        intent ─▶ Brain.decompose ─▶ goals
                        │
          ┌─────────────┼───────────────┐
          ▼             ▼                ▼
   voyager-repo    voyager-net      (more senses…)
     scout()         scan()
          │             │
          ▼             ▼
      adapters: brief ─▶ CognitiveClaim
          │             │
          └──────▶ MissionGraph ◀───────┘
                 (contradictions, causal chain,
                  best-next-probe, memory)
                        │
                        ▼
              Brain.synthesize ─▶ conclusion
```

Each sense produces a `CognitiveClaim`; the
[`MissionGraph`](https://www.npmjs.com/package/@dir-ai/voyager-contract) links
them — auto-detecting **cross-sense contradictions**, assembling the **causal
chain**, and surfacing the single **most informative next probe** by information
gain. A sense *error* becomes a low-confidence `observe` claim flagged with the
unknown — never a false "all clear".

## The Voyager family

| Package | Sense | What it does |
| --- | --- | --- |
| [`@dir-ai/voyager`](https://www.npmjs.com/package/@dir-ai/voyager) | web | verified-internet retrieval, OSV-gated |
| [`@dir-ai/voyager-repo`](https://www.npmjs.com/package/@dir-ai/voyager-repo) | code | orient in a repository, vet dependencies |
| [`@dir-ai/voyager-net`](https://www.npmjs.com/package/@dir-ai/voyager-net) | hosts | authorized, read-only host audit |
| [`@dir-ai/voyager-contract`](https://www.npmjs.com/package/@dir-ai/voyager-contract) | — | the cognitive contract the senses speak |
| **`@dir-ai/voyager-agent`** | **all** | **the one agent that composes them** |

## Safety

- **Read-only senses.** Nothing is installed, executed, or mutated on your systems.
- **Fail-closed host audit.** A host is only scanned with `--authorized` / `authorized: true`; single host only (no ranges/URLs), cloud-metadata blocked.
- **Consent-gated action.** Remediation is described and withheld, surfaced as an `unknown` on the claim — this orchestrator never applies it.
- **Honest uncertainty.** Confidence and `strength` are explicit; a sense error is a flagged unknown, not a clean verdict.

## License

MIT © dir-ai
