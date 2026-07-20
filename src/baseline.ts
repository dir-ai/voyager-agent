import { promises as fs } from 'node:fs'
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { join, resolve, isAbsolute } from 'node:path'
import { newClaim, type CognitiveClaim, type MissionGraph } from '@dir-ai/voyager-contract'

/**
 * DRIFT — the memory that turns photographs into film. Kimi's sharpest comprehension
 * gap: "no memory between missions — every audit starts blank; it sees snapshots, not
 * change." A baseline persists a mission's finding-fingerprints to a directory; the
 * next run over the same targets loads it and reports what is NEW (a regression), what
 * is RESOLVED (a fix confirmed on the field), and what PERSISTS. State lives only under
 * the given dir; a fingerprint is `sense|kind|location` — stable across runs even as a
 * detail's wording shifts. Never throws: an unwritable/absent baseline degrades to
 * "first audit, no drift yet".
 */
export interface BaselineDiff {
  first: boolean
  added: string[]
  resolved: string[]
  persisting: string[]
  since: number | null
  /** A prior baseline existed but its HMAC did NOT verify against the key — a hand
   *  rewrote it to hide a regression. Fail-closed: it is NOT trusted for the diff. */
  tampered: boolean
}

/** HMAC-SHA256 over the fingerprints — the tamper seal (Kimi round-6 #1). */
function seal(fingerprints: string[], key: string): string {
  return createHmac('sha256', key).update(JSON.stringify(fingerprints)).digest('hex')
}
function sealOk(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'hex'); const bb = Buffer.from(b, 'hex')
  return ab.length === bb.length && ab.length > 0 && timingSafeEqual(ab, bb)
}

/** A stable key for a target set — sorted repos/hosts/urls, hashed, filesystem-safe. */
export function missionKey(parts: { repoPaths?: string[]; hosts?: string[]; urls?: string[] }): string {
  const all = [...(parts.repoPaths ?? []), ...(parts.hosts ?? []), ...(parts.urls ?? [])].map((s) => s.trim()).filter(Boolean).sort()
  return createHash('sha256').update(all.join('\n')).digest('hex').slice(0, 24)
}

/** Extract stable finding fingerprints from a mission's observed evidence. */
export function fingerprints(mission: MissionGraph): string[] {
  const fps = new Set<string>()
  for (const c of mission.allClaims()) {
    if (c.operation !== 'observe') continue
    for (const e of c.evidence) {
      const kind = /\]\s*([a-z0-9-]+)\s*:/i.exec(e.what)?.[1]?.toLowerCase() ?? e.what.replace(/\s+/g, ' ').slice(0, 40)
      fps.add(`${c.sense}|${kind}|${(e.at ?? '').slice(0, 120)}`)
    }
  }
  return [...fps].sort()
}

async function contained(dir: string, key: string): Promise<string> {
  const root = isAbsolute(dir) ? dir : resolve(dir)
  await fs.mkdir(root, { recursive: true }).catch(() => {})
  return join(root, `${key.replace(/[^a-z0-9]/gi, '')}.json`)
}

/** Compare the mission to the saved baseline (if any); does NOT write. When an
 *  `hmacKey` is given, the prior baseline's seal MUST verify — a mismatch is treated
 *  as TAMPERED and NOT trusted (fail-closed), so a hand-rewritten "0 NEW" can't hide
 *  a regression. Without a key, the baseline is used but flagged unauthenticated. */
export async function diffBaseline(dir: string, key: string, mission: MissionGraph, hmacKey?: string): Promise<BaselineDiff> {
  const now = fingerprints(mission)
  const nowSet = new Set(now)
  const file = await contained(dir, key)
  let prior: { savedAt?: number; fingerprints?: string[]; hmac?: string } | null = null
  try {
    prior = JSON.parse(await fs.readFile(file, 'utf8'))
  } catch {
    prior = null
  }
  if (!prior || !Array.isArray(prior.fingerprints)) return { first: true, added: now, resolved: [], persisting: [], since: null, tampered: false }
  // Fail-closed integrity check: with a key, the seal must be present AND verify.
  if (hmacKey) {
    if (!prior.hmac || !sealOk(prior.hmac, seal(prior.fingerprints, hmacKey))) {
      return { first: true, added: now, resolved: [], persisting: [], since: typeof prior.savedAt === 'number' ? prior.savedAt : null, tampered: true }
    }
  }
  const priorSet = new Set(prior.fingerprints)
  return {
    first: false,
    added: now.filter((f) => !priorSet.has(f)),
    resolved: prior.fingerprints.filter((f) => !nowSet.has(f)),
    persisting: now.filter((f) => priorSet.has(f)),
    since: typeof prior.savedAt === 'number' ? prior.savedAt : null,
    tampered: false,
  }
}

/** Persist the current fingerprints as the new baseline, SEALED with the HMAC key
 *  when supplied. Never throws. */
export async function saveBaseline(dir: string, key: string, mission: MissionGraph, now: number, hmacKey?: string): Promise<void> {
  try {
    const file = await contained(dir, key)
    const fps = fingerprints(mission)
    const body: Record<string, unknown> = { key, savedAt: now, fingerprints: fps }
    if (hmacKey) body.hmac = seal(fps, hmacKey)
    await fs.writeFile(file, JSON.stringify(body), 'utf8')
  } catch {
    /* unwritable baseline dir → drift just won't persist; the mission still ran */
  }
}

/** Build a `learn` claim describing the drift since the last audit. */
export function driftClaim(diff: BaselineDiff, missionId: string, now: number, goalId?: string): CognitiveClaim {
  const verdict = diff.tampered
    ? `baseline INTEGRITY FAILURE — the prior baseline's HMAC did not verify (it was rewritten by hand). Treating as first audit; do NOT trust any "0 NEW" it would have implied`
    : diff.first
      ? `first audit of these targets — baseline of ${diff.added.length} finding(s) established; drift will be reported from the next run`
      : `drift since last audit: ${diff.added.length} NEW, ${diff.resolved.length} RESOLVED, ${diff.persisting.length} unchanged`
  return newClaim(
    {
      missionId, goalId, sense: 'memory', operation: diff.tampered ? 'observe' : 'learn', capability: 'drift',
      verdict,
      confidence: diff.tampered ? 0.9 : 0.8,
      evidence: diff.tampered
        ? [{ what: '[high] baseline-tampered: the drift baseline seal failed to verify — an attacker rewrote it to hide a regression', framed: true }]
        : diff.added.slice(0, 12).map((f) => ({ what: `[regression] appeared since last audit: ${f}`, framed: true })),
      unknowns: diff.tampered ? ['baseline was tampered — re-establish it from a trusted run'] : diff.resolved.slice(0, 12).map((f) => `resolved since last audit (verify it stays fixed): ${f}`),
      memoryCandidates: [{ kind: 'temporal', statement: verdict, scope: missionId }],
    },
    now,
  )
}
