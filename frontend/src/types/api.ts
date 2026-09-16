/** Shared API types mirroring the backend Pydantic schemas. */

export type Role = "admin" | "analyst" | "auditor" | "viewer";

export const ROLE_RANK: Record<Role, number> = {
  viewer: 0,
  auditor: 1,
  analyst: 2,
  admin: 3,
};

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_in: number;
  role: Role;
}

export interface Me {
  id: string;
  email: string;
  full_name: string;
  role: Role;
  totp_enabled: boolean;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: Role;
  is_active: boolean;
  totp_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
}

export type ApiKeyScope = "ingest:events" | "ingest:signatures";

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_by: string | null;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface ApiKeyCreated extends ApiKey {
  api_key: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface SystemInfo {
  name: string;
  version: string;
  environment: string;
  database: string;
  ml_enabled: boolean;
  outbound_revocation: boolean;
}

// ---- Module 2: cryptographic core ----

export type Verdict = "valid" | "invalid" | "indeterminate";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  code: string;
  title: string;
  severity: FindingSeverity;
  category: string;
  detail: string;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  serial_hex: string;
  not_before: string;
  not_after: string;
  spki_sha256: string;
  sig_algo: string;
  key_type: string;
  key_bits: number | null;
  curve: string | null;
  is_ca: boolean;
  self_signed: boolean;
  key_usage: string[];
  ext_key_usage: string[];
  san: string[];
}

export interface ChainOut {
  status: "trusted" | "untrusted" | "incomplete" | "error";
  trust_anchor_spki: string | null;
  error: string | null;
  chain: CertInfo[];
}

export interface RevocationOut {
  status: "good" | "revoked" | "unknown" | "not_checked" | "error";
  method: string | null;
  detail: string;
  revoked_at: string | null;
}

export interface SignatureOut {
  algorithm: string;
  hash_alg: string | null;
  padding: string | null;
  key_type: string | null;
  key_bits: number | null;
  curve: string | null;
  low_s: boolean | null;
  der_canonical: boolean | null;
}

export interface VerificationResult {
  verdict: Verdict;
  envelope: "raw" | "pdf" | "cms" | "jws" | "image";
  signature: SignatureOut | null;
  signer: CertInfo | null;
  chain: ChainOut | null;
  revocation: RevocationOut | null;
  signing_time: string | null;
  tsa_present: boolean;
  tsa_trusted: boolean;
  findings: Finding[];
  payload_sha256: string | null;
  summary: string;
  trusted_record_status?: string;
  cryptographic_verification?: string;
  overall_result?: string;
}

export interface TrustAnchor {
  id: string;
  name: string;
  subject: string;
  spki_sha256: string;
  fingerprint_sha256: string;
  not_after: string;
  enabled: boolean;
  created_at: string;
}

export interface ObservedCertificate {
  id: string;
  spki_sha256: string;
  fingerprint_sha256: string;
  subject: string;
  issuer: string;
  serial_hex: string;
  not_before: string;
  not_after: string;
  sig_algo: string;
  key_type: string;
  key_bits: number | null;
  curve: string | null;
  is_ca: boolean;
  self_signed: boolean;
  times_seen: number;
  first_seen_at: string;
  last_seen_at: string;
}

// ---- Module 3: threat detection ----

export interface DetectionRule {
  code: string;
  name: string;
  description: string;
  category: string;
  default_severity: FindingSeverity;
  enabled: boolean;
  weight: number;
  config: Record<string, unknown>;
}

export type AlertStatus = "open" | "triaged" | "closed";
export type IncidentStatus = "open" | "investigating" | "contained" | "closed";

export interface FindingRow {
  id: string;
  rule_code: string;
  title: string;
  severity: FindingSeverity;
  category: string;
  detail: string;
  created_at: string;
}

export interface EventListItem {
  id: string;
  created_at: string;
  source: string;
  envelope_type: string;
  verdict: Verdict;
  algo: string | null;
  signer_subject: string | null;
  chain_status: string | null;
  revocation_status: string | null;
  risk_score: number;
  summary: string;
}

export interface EventDetail extends EventListItem {
  source_ref: string | null;
  hash_alg: string | null;
  key_type: string | null;
  key_bits: number | null;
  curve: string | null;
  signer_spki_sha256: string | null;
  signing_time: string | null;
  tsa_present: boolean;
  payload_sha256: string | null;
  anomaly_score: number | null;
  findings: FindingRow[];
  result_json: VerificationResult;
}

export interface Alert {
  id: string;
  event_id: string;
  incident_id: string | null;
  title: string;
  severity: FindingSeverity;
  status: AlertStatus;
  risk_score: number;
  rule_codes: string[];
  assigned_to: string | null;
  triaged_by: string | null;
  triaged_at: string | null;
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface AlertDetail extends Alert {
  event: EventDetail;
}

export interface Incident {
  id: string;
  title: string;
  status: IncidentStatus;
  severity: FindingSeverity;
  cohesion_score: number;
  method: string;
  alert_count: number;
  first_seen_at: string;
  last_seen_at: string;
  signals: Record<string, unknown>;
  created_at: string;
}

export interface IncidentDetail extends Incident {
  alerts: Alert[];
}

export interface ThreatStats {
  events_24h: number;
  events_total: number;
  invalid_24h: number;
  open_alerts: number;
  alerts_by_severity: Record<string, number>;
  open_incidents: number;
  quantum_vulnerable_events: number;
  mean_time_to_triage_seconds: number | null;
  timeline: { date: string; valid: number; invalid: number; indeterminate: number }[];
  top_rules: { code: string; count: number }[];
  recent_alerts: {
    id: string;
    title: string;
    severity: FindingSeverity;
    status: AlertStatus;
    risk_score: number;
    created_at: string;
  }[];
  pqc_by_band: Record<string, number>;
}

// ---- Module 4: quantum-inspired optimisation ----

export type QESBand = "ok" | "monitor" | "plan" | "immediate";

export interface QESResult {
  qes: number;
  band: QESBand;
  algo_factor: number;
  strength_factor: number;
  longevity_factor: number;
  exposure_factor: number;
  recommendation: string;
  assumptions: Record<string, unknown>;
  label: string;
}

export interface PortfolioItem {
  label: string;
  spki_sha256: string | null;
  algo: string | null;
  key_bits: number | null;
  curve: string | null;
  qes: number;
  band: QESBand;
  event_count: number;
}

export interface PortfolioResult {
  items: PortfolioItem[];
  scored: number;
  by_band: Record<string, number>;
  mean_qes: number;
}

export interface SolverInfo {
  method: string;
  best_energy: number;
  energy_trajectory: number[];
  sweeps: number;
  restarts: number;
  seed: number;
  wall_ms: number;
  optimal: boolean | null;
  optimality_gap: number | null;
  params: Record<string, unknown>;
}

export interface MigrationWaveMember {
  name: string;
  qes: number;
  criticality: number;
  effort: number;
  label: string;
}

export interface MigrationPlanResult {
  waves: MigrationWaveMember[][];
  wave_capacity: number;
  total_waves: number;
  cumulative_exposure: number;
  baseline_exposure: number;
  improvement_pct: number;
  solver: SolverInfo;
  unassigned: string[];
  notes: string[];
  run_id: string;
}

export interface TuningMetrics {
  precision: number;
  recall: number;
  f1: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface TuningResult {
  weights: Record<string, number>;
  levels: number[];
  threshold: number;
  before: TuningMetrics;
  after: TuningMetrics;
  solver: SolverInfo;
  rules: string[];
  sample_size: number;
  source: string;
  run_id: string;
}

export interface CorrelationResult {
  clusters: string[][];
  cluster_density: number[];
  singletons: string[];
  qubo_modularity: number;
  baseline_modularity: number;
  event_count: number;
  run_id: string;
}

export interface QuantumRun {
  id: string;
  run_type: string;
  method: string;
  seed: number;
  wall_ms: number;
  params: Record<string, unknown>;
  metrics: Record<string, unknown>;
  input_ref: string | null;
  created_at: string;
}

// ---- Module 5: ML anomaly detection ----

export interface MlStatus {
  enabled: boolean;
  active_model_id: string | null;
  feature_schema_version: number;
  feature_count: number;
  anomaly_weight: number;
}

export interface MlModel {
  id: string;
  algo: "isolation_forest" | "one_class_svm";
  params: Record<string, unknown>;
  metrics: Record<string, number>;
  feature_schema_version: number;
  n_train: number;
  threshold: number;
  artifact_sha256: string;
  is_active: boolean;
  source: string;
  notes: string;
  trained_by: string | null;
  trained_at: string;
}

// ---- Module 6: audit log ----

export interface AuditRow {
  seq: number;
  ts: string;
  actor_id: string | null;
  actor_type: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  meta: Record<string, unknown>;
  prev_hash: string;
  row_hash: string;
}

export interface AuditPage {
  items: AuditRow[];
  total: number;
  limit: number;
  offset: number;
}

export interface ChainVerification {
  ok: boolean;
  checked: number;
  break_at: number | null;
  head_hash: string | null;
  head_seq: number | null;
}
