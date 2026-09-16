import { Badge, Card, type Severity } from "@/components/ui";
import { cn } from "@/lib/cn";
import { formatDateTime } from "@/lib/format";
import type { CertInfo, Finding, VerificationResult } from "@/types/api";

const VERDICT_VAR: Record<VerificationResult["verdict"], string> = {
  valid: "--ok",
  invalid: "--critical",
  indeterminate: "--medium",
};

const SEV_ORDER: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function VerificationResultCard({ result }: { result: VerificationResult }) {
  const findings = [...result.findings].sort(
    (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity],
  );
  const cv = VERDICT_VAR[result.verdict];

  return (
    <div className="space-y-3">
      <Card
        className="relative animate-scale-in overflow-hidden"
        style={{ borderColor: `rgb(var(${cv}) / 0.4)` }}
      >
        <span
          className="pointer-events-none absolute -left-10 -top-10 h-32 w-32 rounded-full opacity-20 blur-2xl"
          style={{ background: `rgb(var(${cv}))` }}
        />
        <div className="relative flex flex-wrap items-center gap-3">
          <span
            className="grid h-10 w-10 place-items-center rounded-xl"
            style={{ background: `rgb(var(${cv}) / 0.14)`, color: `rgb(var(${cv}))` }}
          >
            {result.verdict === "valid" ? (
              <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={2.2} aria-hidden="true">
                <path d="m5 13 4 4L19 7" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            ) : result.verdict === "invalid" ? (
              <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={2.2} aria-hidden="true">
                <path d="M6 6l12 12M18 6 6 18" strokeLinecap="round" />
              </svg>
            ) : (
              <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={2.2} aria-hidden="true">
                <path d="M12 9v4m0 4h.01" strokeLinecap="round" />
                <circle cx="12" cy="12" r="9" />
              </svg>
            )}
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="font-display text-lg font-semibold capitalize" style={{ color: `rgb(var(${cv}))` }}>
                {result.verdict}
              </span>
              <span className="text-[11px] uppercase tracking-wide text-muted">{result.envelope}</span>
            </div>
            <p className="text-sm text-fg">{result.summary}</p>
            {result.envelope === "image" && (
              <dl className="mt-3 grid max-w-xl grid-cols-[12rem_1fr] gap-y-1 text-xs">
                <Row k="Trusted Record" v={result.trusted_record_status ?? "NOT_CHECKED"} />
                <Row
                  k="Cryptographic Verification"
                  v={result.cryptographic_verification ?? "INSUFFICIENT / NOT AVAILABLE"}
                />
                <Row k="Overall" v={result.overall_result ?? "INDETERMINATE"} />
              </dl>
            )}
          </div>
        </div>
      </Card>

      <div className="grid gap-3 lg:grid-cols-2">
        {result.signature && (
          <Card className="animate-fade-up">
            <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">Signature</h4>
            <dl className="grid grid-cols-[8rem_1fr] gap-y-1.5 text-sm">
              <Row k="Algorithm" v={result.signature.algorithm} />
              <Row k="Digest" v={result.signature.hash_alg ?? "—"} />
              {result.signature.padding && <Row k="Padding" v={result.signature.padding} />}
              <Row
                k="Key"
                v={[
                  result.signature.key_type,
                  result.signature.key_bits ? `${result.signature.key_bits}-bit` : null,
                  result.signature.curve,
                ]
                  .filter(Boolean)
                  .join(" · ")}
              />
              {result.signature.low_s !== null && (
                <Row k="Low-S" v={result.signature.low_s ? "yes" : "no (malleable)"} />
              )}
              {result.signing_time && <Row k="Signing time" v={formatDateTime(result.signing_time)} />}
              <Row
                k="Timestamp"
                v={
                  result.tsa_present
                    ? result.tsa_trusted
                      ? "present, trusted"
                      : "present, untrusted"
                    : "none"
                }
              />
            </dl>
          </Card>
        )}

        {result.chain && (
          <Card className="animate-fade-up delay-1">
            <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">
              Certificate chain
            </h4>
            <div className="mb-2 flex flex-wrap gap-2">
              <Badge
                severity={
                  result.chain.status === "trusted"
                    ? "ok"
                    : result.chain.status === "error"
                      ? "critical"
                      : "medium"
                }
                dot
              >
                {result.chain.status}
              </Badge>
              {result.revocation && result.revocation.status !== "not_checked" && (
                <Badge severity={result.revocation.status === "revoked" ? "critical" : "info"}>
                  revocation: {result.revocation.status}
                </Badge>
              )}
            </div>
            <ol className="space-y-1.5">
              {result.chain.chain.map((cert, i) => (
                <CertRow key={cert.spki_sha256 + i} cert={cert} depth={i} />
              ))}
            </ol>
            {result.chain.error && <p className="mt-2 text-xs text-critical">{result.chain.error}</p>}
          </Card>
        )}
      </div>

      <Card className="animate-fade-up delay-2">
        <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">
          Findings ({findings.length})
        </h4>
        {findings.length === 0 ? (
          <p className="flex items-center gap-2 text-sm text-ok">
            <span className="h-1.5 w-1.5 rounded-full bg-ok" />
            No issues detected.
          </p>
        ) : (
          <ul className="space-y-2">
            {findings.map((f, i) => (
              <li
                key={f.code + i}
                className={cn(
                  "flex gap-2.5 rounded-lg border-l-2 bg-hairline/[0.02] py-1.5 pl-2.5 pr-2 text-sm",
                  f.severity === "critical" && "border-critical",
                  f.severity === "high" && "border-high",
                  f.severity === "medium" && "border-medium",
                  f.severity === "low" && "border-low",
                  f.severity === "info" && "border-info",
                )}
              >
                <Badge severity={f.severity as Severity}>{f.severity}</Badge>
                <div className="min-w-0">
                  <span className="font-medium text-fg">
                    <span className="font-mono text-muted">{f.code}</span> · {f.title}
                  </span>
                  {f.detail && <p className="text-xs text-muted">{f.detail}</p>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <>
      <dt className="text-muted">{k}</dt>
      <dd className="truncate font-mono text-[13px] text-fg" title={v}>
        {v}
      </dd>
    </>
  );
}

function CertRow({ cert, depth }: { cert: CertInfo; depth: number }) {
  return (
    <li className="rounded-lg border border-hairline/10 bg-hairline/[0.03] p-2 text-xs">
      <div className="flex items-center gap-2">
        <span className="font-mono text-muted">{depth === 0 ? "leaf" : `#${depth}`}</span>
        <span className="truncate font-medium text-fg" title={cert.subject}>
          {cert.subject}
        </span>
        {cert.is_ca && <Badge severity="info">CA</Badge>}
      </div>
      <div className="mt-0.5 font-mono text-[11px] text-muted">
        {cert.sig_algo} · {cert.key_type}
        {cert.key_bits ? `-${cert.key_bits}` : ""} {cert.curve ?? ""} · exp{" "}
        {formatDateTime(cert.not_after)}
      </div>
    </li>
  );
}
