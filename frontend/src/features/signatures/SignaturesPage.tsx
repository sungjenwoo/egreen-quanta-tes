import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

import { Button, Card, Field, Input, PageHeader, Select, TabBar, textareaClass } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type { VerificationResult } from "@/types/api";

import { VerificationResultCard } from "./VerificationResultCard";

type Tab = "raw" | "document";

const TABS = [
  ["raw", "Raw signature"],
  ["document", "Signed document"],
] as const;

export function SignaturesPage() {
  const [tab, setTab] = useState<Tab>("raw");
  return (
    <>
      <PageHeader
        eyebrow="Cryptographic core"
        title="Signature verification"
        description="Verify RSA / ECC / EdDSA signatures and signed documents (PAdES, CMS, JWS). Every check runs the full threat-detection ruleset."
      />
      <TabBar tabs={TABS} value={tab} onChange={setTab} />
      <div key={tab} className="animate-fade-up">
        {tab === "raw" ? <RawVerifyPanel /> : <DocumentVerifyPanel />}
      </div>
    </>
  );
}

function RawVerifyPanel() {
  const [dataB64, setDataB64] = useState("");
  const [sigB64, setSigB64] = useState("");
  const [hashAlg, setHashAlg] = useState("sha256");
  const [padding, setPadding] = useState("");
  const [pem, setPem] = useState("");
  const [pemKind, setPemKind] = useState<"certificate_pem" | "public_key_pem">(
    "certificate_pem",
  );

  const verify = useMutation<VerificationResult, ApiError>({
    mutationFn: () =>
      api.post<VerificationResult>("/signatures/verify", {
        data_b64: dataB64.trim(),
        signature_b64: sigB64.trim(),
        hash_alg: hashAlg || null,
        padding: padding || null,
        [pemKind]: pem,
      }),
  });

  return (
    <div className="space-y-4">
      <Card className="grid gap-3 md:grid-cols-2">
        <Field label="Message (base64)" htmlFor="rv-data">
          <textarea
            id="rv-data"
            rows={3}
            value={dataB64}
            onChange={(e) => setDataB64(e.target.value)}
            className={textareaClass}
          />
        </Field>
        <Field label="Signature (base64)" htmlFor="rv-sig">
          <textarea
            id="rv-sig"
            rows={3}
            value={sigB64}
            onChange={(e) => setSigB64(e.target.value)}
            className={textareaClass}
          />
        </Field>
        <Field label="Digest" htmlFor="rv-hash">
          <Select id="rv-hash" value={hashAlg} onChange={(e) => setHashAlg(e.target.value)}>
            <option value="sha256">SHA-256</option>
            <option value="sha384">SHA-384</option>
            <option value="sha512">SHA-512</option>
            <option value="">none (EdDSA)</option>
          </Select>
        </Field>
        <Field label="RSA padding" htmlFor="rv-pad">
          <Select id="rv-pad" value={padding} onChange={(e) => setPadding(e.target.value)}>
            <option value="">auto / n-a</option>
            <option value="pss">PSS</option>
            <option value="pkcs1v15">PKCS#1 v1.5</option>
          </Select>
        </Field>
        <div className="md:col-span-2">
          <Field label="Signer material (PEM)">
            <div className="mb-1 flex gap-3 text-xs">
              <label className="flex items-center gap-1">
                <input
                  type="radio"
                  checked={pemKind === "certificate_pem"}
                  onChange={() => setPemKind("certificate_pem")}
                />
                Certificate / chain
              </label>
              <label className="flex items-center gap-1">
                <input
                  type="radio"
                  checked={pemKind === "public_key_pem"}
                  onChange={() => setPemKind("public_key_pem")}
                />
                Public key
              </label>
            </div>
            <textarea
              rows={6}
              value={pem}
              onChange={(e) => setPem(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----"
              className={textareaClass}
            />
          </Field>
        </div>
        <div className="md:col-span-2">
          <Button
            onClick={() => verify.mutate()}
            disabled={verify.isPending || !dataB64 || !sigB64 || !pem}
          >
            {verify.isPending ? "Verifying…" : "Verify signature"}
          </Button>
          {verify.error && (
            <span className="ml-3 text-xs text-critical">{verify.error.message}</span>
          )}
        </div>
      </Card>

      {verify.data && <VerificationResultCard result={verify.data} />}
    </div>
  );
}

function DocumentVerifyPanel() {
  const [file, setFile] = useState<File | null>(null);
  const [detached, setDetached] = useState<File | null>(null);

  const verify = useMutation<VerificationResult, ApiError>({
    mutationFn: () => {
      const fd = new FormData();
      fd.append("file", file as File);
      if (detached) fd.append("detached_content", detached);
      return api.post<VerificationResult>("/signatures/verify-document", fd);
    },
  });

  return (
    <div className="space-y-4">
      <Card className="space-y-3">
        <Field label="Artifact (signed document, certificate image, or scan)" htmlFor="dv-file">
          <Input
            id="dv-file"
            type="file"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
        </Field>
        <Field
          label="Detached content (optional — for detached CMS)"
          htmlFor="dv-detached"
        >
          <Input
            id="dv-detached"
            type="file"
            onChange={(e) => setDetached(e.target.files?.[0] ?? null)}
          />
        </Field>
        <Button onClick={() => verify.mutate()} disabled={verify.isPending || !file}>
          {verify.isPending ? "Verifying…" : "Verify document"}
        </Button>
        {verify.error && (
          <span className="ml-3 text-xs text-critical">{verify.error.message}</span>
        )}
      </Card>
      {verify.data && <VerificationResultCard result={verify.data} />}
    </div>
  );
}
