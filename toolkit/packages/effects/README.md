# @rtk/effects
`ToolEffects` model, MCP annotation derivation (same rule as REA), risk tiers A–E, policy profiles (`locked`, `static-analysis`, `lab-vm`, `device-lab`) and `decide()` — the enforcement point REA lacks. Ships REA's 207-tool effects table (`data/rea-tool-effects.json`; regenerate with `scripts/regenerate.mjs`) plus the verified audit-gap overlay (Frida close/start, `observe_web_execution`, ADB install/start).
**Verified (tests):** derived annotations equal the advertised ones for all 207 REA tools; tier counts match the manual analysis (15 execute foreign code, 6 mutate devices); policy decisions per profile.
**Limits:** the overlay lists only gaps verified on REA f75b1a4; effects are declared, not observed.
