import { z } from "zod";
import { canonicalDigest } from "./canonical.ts";

const hex64 = z.string().regex(/^[a-f0-9]{64}$/u);
export const CONFIDENCE = ["observed", "derived", "inferred"] as const;
export const AUTHORITY = ["shipped-artifact", "controlled-replay", "historical-reference", "external-service", "analyst-inference"] as const;

export const subjectSchema = z.object({
  name: z.string(),
  digest: z.object({ sha256: hex64 }),
  local_path: z.string().nullable().optional(),
  format: z.string().nullable(),
  architecture: z.string().nullable(),
});
export const providerSchema = z.object({ id: z.string().min(1), name: z.string(), version: z.string().nullable() });
export const environmentSchema = z.object({ id: z.string(), platform: z.string(), architecture: z.string(), isolation: z.string() });

/** The Evidence envelope as observed on REA v6.4.0 output (field names/enums verified against real records). */
export const evidenceSchema = z.object({
  evidence_id: z.string().regex(/^ev_[a-f0-9]{64}$/u),
  subject: subjectSchema.nullable(),
  provider: providerSchema,
  analysis_profile: z.unknown(),
  predicate_type: z.string(),
  operation: z.string(),
  parameters: z.unknown(),
  raw_result: z.unknown(),
  normalized_result: z.unknown(),
  confidence: z.enum(CONFIDENCE),
  authority: z.enum(AUTHORITY),
  environment: environmentSchema.nullable(),
  limitations: z.array(z.string()),
  relationship_coverage: z.unknown().optional(),
  locations: z.array(z.unknown()),
  evidence_links: z.array(z.unknown()),
});
export type Evidence = z.infer<typeof evidenceSchema>;
export type Confidence = (typeof CONFIDENCE)[number];
export type Authority = (typeof AUTHORITY)[number];

export type EvidenceInput = Omit<Evidence, "evidence_id" | "limitations" | "locations" | "evidence_links" | "environment" | "analysis_profile" | "raw_result" | "relationship_coverage" | "subject"> & {
  subject?: Evidence["subject"];
  analysis_profile?: unknown;
  raw_result?: unknown;
  environment?: Evidence["environment"];
  limitations?: string[];
  relationship_coverage?: unknown;
  locations?: unknown[];
  evidence_links?: unknown[];
};

/** Fields hashed into the Evidence ID (mirrors REA's `semanticProjection`; display-only subject fields excluded). */
export function semanticProjection(e: Omit<Evidence, "evidence_id">): unknown {
  return {
    subject: e.subject === null ? null : { digest: e.subject.digest, format: e.subject.format, architecture: e.subject.architecture },
    provider: e.provider,
    analysis_profile: e.analysis_profile ?? null,
    predicate_type: e.predicate_type,
    operation: e.operation,
    parameters: e.parameters,
    raw_result: e.raw_result ?? null,
    normalized_result: e.normalized_result,
    confidence: e.confidence,
    authority: e.authority,
    environment: e.environment,
    limitations: e.limitations,
    ...(e.relationship_coverage === null || e.relationship_coverage === undefined ? {} : { relationship_coverage: e.relationship_coverage }),
    locations: e.locations,
    evidence_links: e.evidence_links,
  };
}

export const computeEvidenceId = (e: Omit<Evidence, "evidence_id">): string => `ev_${canonicalDigest(semanticProjection(e))}`;

export function createEvidence(input: EvidenceInput): Evidence {
  const base = {
    subject: input.subject ?? null,
    provider: input.provider,
    analysis_profile: input.analysis_profile ?? null,
    predicate_type: input.predicate_type,
    operation: input.operation,
    parameters: input.parameters,
    raw_result: input.raw_result ?? null,
    normalized_result: input.normalized_result,
    confidence: input.confidence,
    authority: input.authority,
    environment: input.environment ?? null,
    limitations: input.limitations ?? [],
    relationship_coverage: input.relationship_coverage ?? null,
    locations: input.locations ?? [],
    evidence_links: input.evidence_links ?? [],
  } as Omit<Evidence, "evidence_id">;
  return evidenceSchema.parse({ ...base, evidence_id: computeEvidenceId(base) });
}

/** Parse and authenticate: rejects a syntactically valid record whose ID does not match its content. */
export function parseEvidence(input: unknown): Evidence {
  const e = evidenceSchema.parse(input);
  const { evidence_id, ...rest } = e;
  if (computeEvidenceId(rest as Omit<Evidence, "evidence_id">) !== evidence_id) throw new Error(`Evidence ID mismatch for ${evidence_id}`);
  return e;
}
