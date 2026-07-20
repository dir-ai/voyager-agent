import { newClaim, type CausalLink, type CognitiveClaim, type Entity, type Relationship } from '@dir-ai/voyager-contract'

/**
 * Cross-sense CORRELATION — the step that turns three piles of entities into one
 * causal picture. The senses each surface their own world (web pages/forms, repo
 * routes/services, net hosts/ports); this links them into cause→effect edges the
 * MissionGraph can assemble into a chain and a real rootCause:
 *
 *   web form → /api/login  ⇢  repo route POST /api/login  ⇢  its handler file
 *   repo service `db` (postgres)  ⇢  an OPEN net port 5432 on the host  ⇢ exposed
 *   repo route  ⇢  reachable at the host's open HTTP port
 *
 * Without this the graph only aggregates; with it, `mission.state().rootCause` is
 * no longer structurally empty. Returns an `infer` claim carrying the edges, or
 * null when nothing correlates.
 */
const SERVICE_PORTS: Record<string, number> = {
  postgres: 5432, postgresql: 5432, mysql: 3306, mariadb: 3306, redis: 6379,
  mongo: 27017, mongodb: 27017, elasticsearch: 9200, memcached: 11211,
  rabbitmq: 5672, kafka: 9092, cassandra: 9042, couchdb: 5984,
}
const HTTP_PORTS = new Set([80, 443, 8080, 8443, 3000, 8000, 5000, 8888])

/** Normalize any URL/path to a comparable route path: strip origin, lead/trail slash, lowercase. */
function normPath(s: string): string {
  const noOrigin = s.replace(/^[a-z]+:\/\/[^/]+/i, '')
  return '/' + noOrigin.replace(/[?#].*$/, '').replace(/^\/+/, '').replace(/\/+$/, '').toLowerCase()
}
/** A route entity's path (id form `repo:route:/x`, or from its label `POST /x`). */
function routePath(e: Entity): string {
  const fromId = /^repo:(?:route|page):(.+)$/.exec(e.id)?.[1]
  if (fromId) return normPath(fromId)
  const fromLabel = /(?:^|\s)(\/[^\s]*)/.exec(e.label ?? '')?.[1]
  return normPath(fromLabel ?? e.label ?? '')
}
function portOf(e: Entity): number | null {
  const m = /^net:port:.+:(\d+)$/.exec(e.id) ?? /(\d{2,5})/.exec(e.label ?? '')
  const n = m ? Number(m[1]) : NaN
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : null
}

export function correlate(claims: readonly CognitiveClaim[], missionId: string, now: number, goalId?: string): CognitiveClaim | null {
  const entities = claims.flatMap((c) => c.entities)
  const routes = entities.filter((e) => e.kind === 'route' || e.kind === 'page')
  const webEndpoints = entities.filter((e) => e.sense === 'web' && (e.kind === 'form' || e.kind === 'page'))
  const services = entities.filter((e) => e.kind === 'service' && e.sense === 'repo')
  const netPorts = entities.filter((e) => e.sense === 'net' && e.kind === 'port')
  const hosts = entities.filter((e) => e.sense === 'net' && e.kind === 'host')

  const links: CausalLink[] = []
  const rels: Relationship[] = []
  const add = (cause: string, effect: string, via: string, kind: Relationship['kind'], confidence: number): void => {
    links.push({ cause, effect, via, confidence })
    rels.push({ from: cause, to: effect, kind, confidence })
  }

  // 1) A web endpoint the UI calls ⇢ the repo route that implements it (by PATH).
  for (const w of webEndpoints) {
    const wPath = normPath(w.kind === 'form' ? (/^web:form:(.+)$/.exec(w.id)?.[1] ?? w.label ?? '') : (w.label ?? w.id))
    const match = routes.find((r) => routePath(r) === wPath && wPath !== '/')
    if (match) add(match.id, w.id, `HTTP route ${wPath} implements the called endpoint`, 'implemented-by', 0.75)
  }

  // 2) A repo service (db/cache/…) ⇢ an OPEN net port that exposes it.
  for (const s of services) {
    const label = (s.label ?? '').toLowerCase()
    for (const [svc, port] of Object.entries(SERVICE_PORTS)) {
      if (!label.includes(svc)) continue
      const p = netPorts.find((pt) => portOf(pt) === port)
      if (p) add(s.id, p.id, `${svc} service exposed on open port ${port}`, 'runs-on', 0.8)
    }
  }

  // 3) The repo's routes ⇢ reachable at the host's open HTTP port (the app is live).
  const httpPort = netPorts.find((pt) => { const n = portOf(pt); return n != null && (HTTP_PORTS.has(n) || /http/i.test(pt.label ?? '')) })
  const host = hosts[0]
  if (httpPort && host && routes.length) {
    add(routes[0].id, httpPort.id, `route reachable at ${host.label}${httpPort.label ? ':' + (portOf(httpPort) ?? '') : ''}`, 'reachable-from', 0.6)
  }

  if (!links.length) return null
  return newClaim(
    {
      missionId, goalId, sense: 'memory', operation: 'infer', capability: 'correlate',
      verdict: `cross-sense correlation: ${links.length} cause→effect edge(s) linking web ↔ repo ↔ net into one attack/architecture surface`,
      confidence: 0.72,
      causalChain: links,
      relationships: rels,
    },
    now,
  )
}
