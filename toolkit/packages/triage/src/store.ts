import { DatabaseSync } from "node:sqlite";
import { buildBundle, serializeBundle, type Evidence, parseEvidence, sha256Hex } from "@rtk/evidence";
import type { Ioc } from "./ioc.ts";
import type { Finding } from "./rules.ts";

/** SQLite case store: samples, Evidence, findings, IOCs; supports cross-sample IOC pivots and bundle export. */
export class CaseStore {
  readonly #db: DatabaseSync;
  constructor(path = ":memory:") {
    this.#db = new DatabaseSync(path);
    this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS samples(sha256 TEXT PRIMARY KEY, name TEXT, type TEXT, size INTEGER, md5 TEXT, sha1 TEXT, first_seen TEXT, last_triaged TEXT, score REAL, band TEXT);
      CREATE TABLE IF NOT EXISTS evidence(evidence_id TEXT PRIMARY KEY, sample_sha256 TEXT NOT NULL REFERENCES samples(sha256), operation TEXT, provider TEXT, json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS findings(sample_sha256 TEXT NOT NULL REFERENCES samples(sha256), run TEXT, rule_id TEXT, severity TEXT, tactic TEXT, title TEXT, json TEXT);
      CREATE TABLE IF NOT EXISTS iocs(sample_sha256 TEXT NOT NULL REFERENCES samples(sha256), kind TEXT, value TEXT, classification TEXT, json TEXT, PRIMARY KEY(sample_sha256, kind, value));
      CREATE INDEX IF NOT EXISTS iocs_value ON iocs(kind, value);`);
  }
  upsertSample(s: { sha256: string; name: string; type: string; size: number; md5: string; sha1: string }, score?: { score: number; band: string }): void {
    const now = new Date().toISOString();
    this.#db.prepare(`INSERT INTO samples(sha256,name,type,size,md5,sha1,first_seen,last_triaged,score,band) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET name=excluded.name, type=excluded.type, last_triaged=excluded.last_triaged, score=COALESCE(excluded.score, score), band=COALESCE(excluded.band, band)`).run(s.sha256, s.name, s.type, s.size, s.md5, s.sha1, now, now, score?.score ?? null, score?.band ?? null);
  }
  addEvidence(sampleSha256: string, e: Evidence): void { this.#db.prepare("INSERT OR IGNORE INTO evidence(evidence_id,sample_sha256,operation,provider,json) VALUES(?,?,?,?,?)").run(e.evidence_id, sampleSha256, e.operation, e.provider.id, JSON.stringify(e)); }
  saveFindings(sampleSha256: string, run: string, fs: Finding[]): void { this.#db.prepare("DELETE FROM findings WHERE sample_sha256=?").run(sampleSha256); const st = this.#db.prepare("INSERT INTO findings VALUES(?,?,?,?,?,?,?)"); for (const f of fs) st.run(sampleSha256, run, f.rule_id, f.severity, f.tactic, f.title, JSON.stringify(f)); }
  saveIocs(sampleSha256: string, iocs: Ioc[]): void { const st = this.#db.prepare("INSERT OR REPLACE INTO iocs VALUES(?,?,?,?,?)"); for (const i of iocs) st.run(sampleSha256, i.kind, i.value, i.classification, JSON.stringify(i)); }
  samples(): { sha256: string; name: string; type: string; score: number | null; band: string | null }[] { return this.#db.prepare("SELECT sha256,name,type,score,band FROM samples ORDER BY first_seen, sha256").all() as never; }
  evidenceFor(sha: string): Evidence[] { return (this.#db.prepare("SELECT json FROM evidence WHERE sample_sha256=? ORDER BY evidence_id").all(sha) as { json: string }[]).map((r) => parseEvidence(JSON.parse(r.json))); }
  findingsFor(sha: string): Finding[] { return (this.#db.prepare("SELECT json FROM findings WHERE sample_sha256=? ORDER BY rule_id").all(sha) as { json: string }[]).map((r) => JSON.parse(r.json) as Finding); }
  /** Which stored samples share an indicator? (campaign correlation pivot) */
  samplesWithIoc(kind: string, value: string): string[] { return (this.#db.prepare("SELECT sample_sha256 FROM iocs WHERE kind=? AND value=? ORDER BY sample_sha256").all(kind, value) as { sample_sha256: string }[]).map((r) => r.sample_sha256); }
  sharedIocs(): { kind: string; value: string; samples: string[] }[] { return (this.#db.prepare("SELECT kind,value,group_concat(sample_sha256) AS s,count(*) AS n FROM iocs WHERE classification IN ('public','unknown','example-domain','documentation') GROUP BY kind,value HAVING n>1 ORDER BY n DESC,kind,value").all() as { kind: string; value: string; s: string }[]).map((r) => ({ kind: r.kind, value: r.value, samples: r.s.split(",").sort() })); }
  exportBundle(sha: string): { text: string; sha256: string } { const b = buildBundle({ records: this.evidenceFor(sha) }); const text = serializeBundle(b); return { text, sha256: sha256Hex(text) }; }
  close(): void { this.#db.close(); }
}
