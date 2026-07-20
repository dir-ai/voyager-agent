/**
 * THE FINDING→MOVE GRAPH — the "kill chain", strictly as ADVICE.
 *
 * Kimi's GIUDIZIO (both Cantos, score 1/10): "the SARIF is a shopping list, not a
 * kill chain" — `suggestedNextProbes` was ALWAYS EMPTY and `executedProbes` was `{}`.
 * A finding told the operator WHAT is wrong but never the NEXT MOVE to escalate it.
 *
 * This module closes that gap for the PUBLIC, READ-ONLY agent: a STATIC mapping from
 * each SARIF finding-kind (net/*, web/*, repo/*) to the concrete next probe(s) an
 * analyst would run to escalate it — each an advisory string carrying the ATTACK
 * HYPOTHESIS and the named TECHNIQUE. It is ADVICE, not execution: no payloads are
 * built, no requests are sent, nothing is chained here. The offensive execution of
 * these probes is the SEPARATE, internal, consent-gated `voyager-hands` engine — out
 * of scope for this package, which ships zero offensive code.
 *
 * The strings are authored here (never target-derived), but the report still runs
 * them through the family sanitizer before they enter the signed SARIF — defense in
 * depth, consistent with every other string in the document.
 */

/** Advisory next-move edges keyed by SARIF finding-kind. Each string starts with
 *  `escalate` and NAMES the technique, so a reader gets the hypothesis + the method
 *  without any payload. Extend sensibly — an unmapped kind still gets a generic
 *  triage hint via {@link nextMovesFor}, so the kill-chain is never empty. */
export const FINDING_MOVES: Record<string, string[]> = {
  // ── web (browser sense) ────────────────────────────────────────────────────
  'weak-cookie': ['escalate: reflected/stored XSS -> session theft (technique: XSS session hijack) — the missing HttpOnly/Secure/SameSite flags make a stolen cookie usable cross-site'],
  'cookie-samesite': ['escalate: reflected/stored XSS -> session theft (technique: XSS session hijack) — a weak SameSite lets a stolen/forced cookie ride cross-site requests'],
  'insecure-cookie': ['escalate: reflected/stored XSS -> session theft (technique: XSS session hijack) — an insecure cookie is readable/replayable off the secure channel'],
  'missing-csp': ['escalate: test for reflected/stored XSS (technique: XSS payload delivery) — with no Content-Security-Policy an injected <script> executes unrestricted'],
  'weak-csp': ['escalate: test CSP bypass then reflected/stored XSS (technique: CSP bypass + XSS) — an unsafe-inline / wildcard policy still permits script execution'],
  'missing-hsts': ['escalate: SSL-strip / downgrade MITM (technique: TLS downgrade) — with no HSTS an active network attacker forces plaintext HTTP and captures the session'],
  'cors-credentials': ['escalate: host a cross-origin page that reads the authenticated response (technique: CORS-misconfig exfiltration) — ACAO reflected together with credentials leaks user data cross-origin'],
  'cors-wildcard': ['escalate: host a cross-origin page and test whether it can read the response (technique: CORS-misconfig exfiltration) — confirm credentials are honored with the wildcard/reflected origin'],
  'exposed-endpoint': ['escalate: test the endpoint for IDOR / missing authz / verb tampering (technique: BOLA/IDOR + PUT/DELETE) — swap the object id and change the HTTP verb to probe broken access control'],
  'graphql-introspection-enabled': ['escalate: enumerate mutations from the introspection schema and test each unauthenticated (technique: GraphQL introspection abuse) — the schema hands you the full attack surface'],
  'mixed-content': ['escalate: active-MITM sub-resource injection (technique: mixed-content injection) — an on-path attacker tampers the http:// asset loaded by the https page'],
  'form-insecure': ['escalate: capture the submitted values on the wire (technique: cleartext-credential MITM) — the form posts over http, so credentials transit in the clear'],
  'embedded-frame-unsandboxed': ['escalate: clickjacking / UI-redress + untrusted-frame capability abuse (technique: clickjacking) — a missing sandbox lets framed content act with the parent origin'],
  'exposed-secret': ['escalate: validate the leaked key against its provider, then ROTATE immediately (technique: leaked-credential abuse) — a live key is an immediate account-takeover path'],
  'version-leak': ['escalate: CVE lookup for the leaked <product> <version> -> known-exploit check (technique: OSV/NVD version-to-CVE) — map the disclosed version to a public exploit'],

  // ── net (host/service sense) ───────────────────────────────────────────────
  'exposed-service': ['escalate: attempt default creds / unauthenticated data access on the service (technique: default-credential + unauth access) — reachable does not mean protected'],
  'unauthenticated-service': ['escalate: connect and read/enumerate data with no credentials (technique: unauth data access) — the service answers anyone; confirm what it exposes'],
  'app-exposed': ['escalate: attempt default creds / unauth access on the exposed admin app (technique: default-credential + unauth access) — an admin surface reachable from the outside is a takeover candidate'],
  'ssh-weak-algorithm': ['escalate: capture/verify credential exposure and check known CVEs for the SSH banner version (technique: CVE lookup + weak-crypto negotiation)'],
  'telnet-cleartext': ['escalate: capture/verify credential exposure on the wire (technique: cleartext-credential capture) — telnet transits credentials in the clear'],
  'service-version': ['escalate: CVE lookup for the <product> <version> banner -> known-exploit check (technique: OSV/NVD version-to-CVE)'],
  'weak-tls': ['escalate: confirm the weak protocol/cipher is negotiable and check POODLE/BEAST-class exposure (technique: TLS downgrade + legacy-cipher attack)'],
  'tls-expired': ['escalate: MITM trust-bypass feasibility (technique: cert-validation bypass) — an invalid cert conditions users to click through the interception warning'],
  'tls-expiring': ['escalate: track rotation and re-check trust before expiry (technique: cert-lifecycle review) — an expiring cert becomes a trust-bypass window'],
  'tls-untrusted': ['escalate: MITM trust-bypass feasibility (technique: cert-validation bypass) — an untrusted chain lets an on-path attacker substitute a cert unnoticed'],
  'weak-key': ['escalate: assess factorization/forgery feasibility of the weak key (technique: weak-key cryptanalysis)'],
  'missing-dmarc': ['escalate: test spoofed-message deliverability from the domain (technique: email spoofing) — absent DMARC lets a from-domain forgery reach inboxes'],
  'missing-spf': ['escalate: test spoofed-message deliverability from the domain (technique: email spoofing) — absent SPF removes the sender-authorization check'],

  // ── repo (source sense) ────────────────────────────────────────────────────
  'hardcoded-secret': ['escalate: validate the committed secret against its service, then ROTATE (technique: leaked-credential abuse)'],
  'git-history-secret': ['escalate: validate the historical secret against its service and ROTATE — assume compromised (technique: leaked-credential abuse from VCS history)'],
  'unsafe-dependency': ['escalate: map the flagged dependency to OSV advisories + known-malicious indicators (technique: SCA / OSV lookup) — confirm CVE or malware before trusting the build'],
  'unsafe-transitive-dependency': ['escalate: resolve the transitive path and map it to OSV advisories (technique: transitive SCA / OSV lookup) — the risk enters via a dependency-of-a-dependency'],
  'install-hook': ['escalate: read the install/postinstall hook for network + exec behavior it runs at `npm install` (technique: install-script supply-chain review)'],
  'sensitive-file': ['escalate: read the exposed sensitive file for credentials/keys (technique: sensitive-file disclosure)'],
  'agent-instructions': ['escalate: review the agent-instruction file as an untrusted control channel that could steer a downstream AI (technique: agent-instruction injection review)'],
  'code-eval': ['escalate: trace the eval/dynamic-exec sink back to a user-controlled source (technique: code-injection / RCE dataflow)'],
  'code-shell': ['escalate: trace the shell-exec sink back to a user-controlled source (technique: command-injection dataflow)'],
  'code-download-exec': ['escalate: identify the fetched-then-executed artifact and its origin (technique: download-exec supply-chain review)'],
  'ci-pwn-request': ['escalate: review the workflow trigger for untrusted-PR code execution with secrets (technique: pwn-request CI abuse)'],
  'ci-script-injection': ['escalate: trace the CI expression to an attacker-controllable context value (technique: CI script injection)'],
  'iac-public-bucket': ['escalate: test anonymous read/list on the bucket (technique: public-object-store access)'],
  'iac-open-ingress': ['escalate: port-scan the open ingress range and probe reachable services (technique: exposed-ingress access)'],
  'iac-public-db': ['escalate: attempt an unauthenticated connection to the exposed database (technique: public-database access)'],

  // ── active / DEMONSTRATED (already chained by an injected verifier) ─────────
  'exploit-verified': ['already DEMONSTRATED — escalate: chain the confirmed vuln toward data access / lateral movement (technique: post-exploitation) — hand to the consent-gated hands engine for controlled proof'],
  'sqli': ['already DEMONSTRATED — escalate: enumerate the schema and dump a bounded record set via the confirmed injection (technique: post-exploitation, UNION/boolean extraction) — hands-only, consent-gated'],
  'xss': ['already DEMONSTRATED — escalate: chain the confirmed XSS to session theft / a CSRF-authenticated action (technique: post-exploitation session hijack) — hands-only, consent-gated'],
}

/** Generic per-sense triage hint for a finding-kind with no explicit edge — keeps
 *  the kill-chain honest (never empty) without inventing a false technique. */
function genericMove(sense: string, kind: string): string {
  const where =
    sense === 'net' ? 'the exposed host/service'
    : sense === 'web' ? 'the web response/header'
    : sense === 'repo' ? 'the flagged source/config'
    : 'the finding'
  return `escalate: manually triage ${kind} on ${where} for exploitability (technique: analyst review — no automated escalation edge encoded for this kind)`
}

/**
 * Advisory next move(s) for a finding — the ADVICE edge, never an action. Looks up
 * the explicit finding→move graph, falls back to a `tls-*` family hint, then to a
 * generic per-sense triage hint so a result always carries a sensible next step.
 */
export function nextMovesFor(sense: string, kind: string): string[] {
  const explicit = FINDING_MOVES[kind]
  if (explicit) return explicit
  // Family fallback: any tls-* kind we didn't enumerate still gets the cert/downgrade hint.
  if (/^tls-/.test(kind)) return ['escalate: assess MITM/downgrade feasibility for the TLS condition (technique: TLS trust/downgrade review)']
  return [genericMove(sense, kind)]
}
