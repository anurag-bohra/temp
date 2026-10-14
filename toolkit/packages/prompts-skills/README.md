# @rtk/prompts-skills
REA's six guided prompts (data extracted from REA's compiled contracts), a renderer, four toolkit prompts (`triage_sample`, `contain_and_detonate`, `vuln_root_cause`, `patch_diff_review`), two skills (`skills/malware-triage`, `skills/vuln-research`) and an additive, idempotent, backup-making installer (`rtk-skills install <dir>`).
**Verified (tests):** rendering is **byte-identical** to REA's real rendered output captured over MCP; arguments appear only as quoted JSON data; every tool named in a prompt step or a skill exists in REA's catalog or the toolkit tool list.
**Not tested:** how a real LLM agent behaves with these prompts/skills.
