import { test } from "node:test";
import assert from "node:assert/strict";
import { auditAnnotations, decide, deriveAnnotations, effectiveEffects, loadReaEffects, PROFILES, tierOf, tierSummary } from "../src/index.ts";

const table = loadReaEffects();

test("table covers all 207 REA tools", () => assert.equal(Object.keys(table).length, 207));

test("annotations derived from effects equal the advertised annotations for every REA tool", () => {
  assert.deepEqual(auditAnnotations(table), []);
});

test("tier counts match the manual analysis (declared effects): 15 execute foreign code, 6 mutate devices", () => {
  const s = tierSummary(table, false);
  assert.equal(s.D.length, 15); assert.equal(s.E.length, 6);
  assert.ok(s.D.includes("capture_process_scenario") && s.D.includes("instrument_with_frida") && s.E.includes("install_adb_package"));
});

test("verified audit-gap overlay upgrades Frida/ADB/web execution tools to tier D", () => {
  const withOverlay = tierSummary(table, true);
  for (const t of ["close_frida_session", "start_frida_session", "observe_web_execution", "install_adb_package", "start_adb_app"]) assert.ok(withOverlay.D.includes(t), t);
  assert.ok(withOverlay.D.length > 15);
});

test("policy engine enforces profiles", () => {
  const rec = (n: string) => table[n]!.effects;
  assert.equal(decide("analyze_javascript_application", rec("analyze_javascript_application"), PROFILES["static-analysis"]!).verdict, "allow");
  assert.equal(decide("capture_process_scenario", rec("capture_process_scenario"), PROFILES["static-analysis"]!).verdict, "deny");
  assert.equal(decide("capture_process_scenario", rec("capture_process_scenario"), PROFILES["lab-vm"]!).verdict, "ask");
  assert.equal(decide("set_address_name", rec("set_address_name"), PROFILES["static-analysis"]!).verdict, "ask");
  assert.equal(decide("start_frida_session", rec("start_frida_session"), PROFILES["static-analysis"]!).verdict, "deny"); // only denied thanks to the overlay
  assert.equal(decide("extract_artifact", rec("extract_artifact"), PROFILES.locked!).verdict, "deny");
  assert.equal(decide("x", rec("list_unknowns"), { ...PROFILES.locked!, denyTools: ["x"] }).verdict, "deny");
});

test("deriveAnnotations semantics", () => {
  const base = { mutatesTarget: false, mutatesSession: false, writesFilesystem: false, launchesProcess: false, accessesNetwork: false, changesUiState: false, mayDiscardData: false, executesForeignCode: false, mutatesDevice: false, idempotent: true };
  assert.equal(deriveAnnotations(base).readOnlyHint, true);
  assert.equal(deriveAnnotations({ ...base, executesForeignCode: true }).destructiveHint, true);
  assert.equal(deriveAnnotations({ ...base, accessesNetwork: true }).openWorldHint, true);
  assert.equal(tierOf({ ...base, mutatesDevice: true }), "E");
  assert.equal(effectiveEffects("nonexistent", base), base);
});
