/**
 * COMPLIANCE MAPPING — the vocabulary a CISO buys. Every finding kind is mapped to
 * the control frameworks an enterprise reports against: CIS Controls v8, OWASP
 * Top 10 (2021), and NIST SP 800-53. A finding that says "unauthenticated Redis" is
 * useful; one that ALSO says "→ CIS 4.1 / OWASP A07 / NIST AC-3" is auditable. The
 * map is conservative (a best-effort control reference, not a certification) and
 * feeds both the SARIF rule tags and a compliance-coverage claim.
 */
export interface Controls {
  cis?: string
  owasp?: string
  nist?: string
}

const MAP: Record<string, Controls> = {
  // ── net ──────────────────────────────────────────────────────────────────
  'unauthenticated-service': { cis: 'CIS 4.1', owasp: 'A07:2021 Identification & Authentication Failures', nist: 'AC-3' },
  'exposed-service': { cis: 'CIS 4.1', owasp: 'A05:2021 Security Misconfiguration', nist: 'SC-7' },
  'weak-tls': { cis: 'CIS 3.10', owasp: 'A02:2021 Cryptographic Failures', nist: 'SC-8' },
  'tls-expired': { cis: 'CIS 3.10', owasp: 'A02:2021 Cryptographic Failures', nist: 'SC-12' },
  'tls-expiring': { cis: 'CIS 3.10', nist: 'SC-12' },
  'tls-untrusted': { owasp: 'A02:2021 Cryptographic Failures', nist: 'SC-17' },
  'weak-key': { cis: 'CIS 3.11', owasp: 'A02:2021 Cryptographic Failures', nist: 'SC-13' },
  'ssh-weak-algorithm': { cis: 'CIS 4.5', owasp: 'A02:2021 Cryptographic Failures', nist: 'SC-13' },
  'app-exposed': { cis: 'CIS 4.1', owasp: 'A05:2021 Security Misconfiguration', nist: 'CM-7' },
  'version-leak': { owasp: 'A05:2021 Security Misconfiguration', nist: 'CM-7' },
  'missing-dmarc': { cis: 'CIS 9.5', nist: 'SC-8' },
  'missing-spf': { cis: 'CIS 9.5', nist: 'SC-8' },
  'missing-caa': { nist: 'SC-12' },
  'cors-wildcard': { owasp: 'A05:2021 Security Misconfiguration', nist: 'AC-4' },
  'weak-cookie': { owasp: 'A05:2021 Security Misconfiguration', nist: 'SC-23' },
  'missing-hsts': { owasp: 'A05:2021 Security Misconfiguration', nist: 'SC-8' },
  'missing-csp': { owasp: 'A05:2021 Security Misconfiguration', nist: 'SI-10' },
  // ── repo ─────────────────────────────────────────────────────────────────
  'install-hook': { cis: 'CIS 2.3', owasp: 'A08:2021 Software & Data Integrity Failures', nist: 'SA-12' },
  'unsafe-dependency': { cis: 'CIS 2.2', owasp: 'A06:2021 Vulnerable & Outdated Components', nist: 'RA-5' },
  'unsafe-transitive-dependency': { cis: 'CIS 2.2', owasp: 'A06:2021 Vulnerable & Outdated Components', nist: 'RA-5' },
  'trivy-vuln': { cis: 'CIS 2.2', owasp: 'A06:2021 Vulnerable & Outdated Components', nist: 'RA-5' },
  'hardcoded-secret': { cis: 'CIS 16.4', owasp: 'A07:2021 Identification & Authentication Failures', nist: 'IA-5' },
  'git-history-secret': { cis: 'CIS 16.4', owasp: 'A07:2021 Identification & Authentication Failures', nist: 'IA-5' },
  'trivy-secret': { cis: 'CIS 16.4', nist: 'IA-5' },
  'sensitive-file': { cis: 'CIS 3.3', owasp: 'A01:2021 Broken Access Control', nist: 'AC-3' },
  'agent-instructions': { owasp: 'A03:2021 Injection', nist: 'SI-10' },
  'mcp-config-suspicious': { owasp: 'A08:2021 Software & Data Integrity Failures', nist: 'CM-7' },
  'code-eval': { cis: 'CIS 16.11', owasp: 'A03:2021 Injection', nist: 'SI-10' },
  'code-shell': { cis: 'CIS 16.11', owasp: 'A03:2021 Injection', nist: 'SI-10' },
  'code-download-exec': { owasp: 'A08:2021 Software & Data Integrity Failures', nist: 'SI-7' },
  'code-network-exfil': { owasp: 'A10:2021 SSRF', nist: 'SC-7' },
  'code-obfuscation': { owasp: 'A08:2021 Software & Data Integrity Failures', nist: 'SI-7' },
  'committed-binary': { owasp: 'A08:2021 Software & Data Integrity Failures', nist: 'SI-7' },
  'ci-pwn-request': { cis: 'CIS 16.12', owasp: 'A08:2021 Software & Data Integrity Failures', nist: 'SA-15' },
  'ci-script-injection': { owasp: 'A03:2021 Injection', nist: 'SI-10' },
  'docker-unpinned-base': { cis: 'CIS 4.11', owasp: 'A08:2021 Software & Data Integrity Failures', nist: 'CM-2' },
  'docker-secret': { cis: 'CIS 16.4', owasp: 'A07:2021 Identification & Authentication Failures', nist: 'IA-5' },
  'docker-download-exec': { owasp: 'A08:2021 Software & Data Integrity Failures', nist: 'SI-7' },
  'docker-exposed-admin': { cis: 'CIS 4.1', owasp: 'A05:2021 Security Misconfiguration', nist: 'CM-7' },
  'docker-root': { cis: 'CIS 5.1', owasp: 'A05:2021 Security Misconfiguration', nist: 'AC-6' },
  'compose-privileged': { cis: 'CIS 5.2', owasp: 'A05:2021 Security Misconfiguration', nist: 'AC-6' },
  'compose-docker-socket': { cis: 'CIS 5.31', owasp: 'A05:2021 Security Misconfiguration', nist: 'AC-6' },
  'compose-host-network': { cis: 'CIS 5.9', nist: 'SC-7' },
  'compose-open-bind': { cis: 'CIS 4.1', owasp: 'A05:2021 Security Misconfiguration', nist: 'SC-7' },
  'iac-public-bucket': { cis: 'CIS 3.3', owasp: 'A01:2021 Broken Access Control', nist: 'AC-3' },
  'iac-open-ingress': { cis: 'CIS 4.1', owasp: 'A05:2021 Security Misconfiguration', nist: 'SC-7' },
  'iac-public-db': { cis: 'CIS 3.3', owasp: 'A01:2021 Broken Access Control', nist: 'AC-3' },
  'iac-hardcoded-secret': { cis: 'CIS 16.4', owasp: 'A07:2021 Identification & Authentication Failures', nist: 'IA-5' },
  // ── browser / web ──────────────────────────────────────────────────────────
  'embedded-frame-unsandboxed': { owasp: 'A05:2021 Security Misconfiguration', nist: 'SC-7' },
  'form-insecure': { owasp: 'A02:2021 Cryptographic Failures', nist: 'SC-8' },
  'mixed-content': { owasp: 'A02:2021 Cryptographic Failures', nist: 'SC-8' },
  'exposed-endpoint': { cis: 'CIS 4.1', owasp: 'A01:2021 Broken Access Control', nist: 'AC-3' },
}

/** Controls a finding kind maps to, or null if unmapped. */
export function complianceFor(kind: string): Controls | null {
  return MAP[kind] ?? null
}

/** Flatten a Controls into tag strings for SARIF / display. */
export function controlTags(c: Controls | null): string[] {
  if (!c) return []
  return [c.cis, c.owasp && `OWASP ${c.owasp}`, c.nist && `NIST ${c.nist}`].filter((x): x is string => !!x)
}
