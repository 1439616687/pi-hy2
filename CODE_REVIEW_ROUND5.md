# pihy2 — Round 5 Audit Synthesis Report

## Executive Summary

This round surfaced **63 verified findings** across the full codebase (parser, YAML reader, config generator, store, manager, WebUI, frontend, installer, tests). After deduplication (the TUIC `allowInsecure` mismatch was reported three times; the parser `_int`/`_safe_int` asymmetry twice; the uninstall sysctl residue twice; the process-name dropdown twice; the `update_node` `sub`-injection twice; the latest-binary integrity gap twice), the actionable set is consolidated below.

The defining theme: **the data layer (`store`) and the renderer (`config_gen`) do not enforce their own invariants** — validation lives only in the WebUI handler, so any second writer (CLI, wizard, timer, hand-edited `state.json`, or a malformed authenticated request) can poison `state.json` and wedge the core apply path. A second theme: **silent export/round-trip data loss** in the parser, and **host-coexistence destruction** in the installer/service layer.

### Counts by severity

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 6 |
| Medium | 18 |
| Low | 31 |
| Info | 8 |

### Counts by dimension

| Dimension | Count |
|---|---|
| security / SSRF | 9 |
| robustness | 16 |
| bug (logic) | 12 |
| data-contract | 9 |
| test-gap | 9 |
| compatibility | 4 |
| conflict (host coexist) | 7 |
| feature-completeness | 3 |
| style/info | (overlaps above) |

*(A finding may sit in two buckets; counts are indicative.)*

### Fix these first

1. **SEC-1 — Non-ASCII WebUI password permanently bricks login** (`webui.py:321`). `secrets.compare_digest(str, str)` raises `TypeError` on any non-ASCII char. On a fully Chinese-language tool, a Chinese password = total, unrecoverable lockout. One-line fix (compare bytes). **Top priority.**
2. **BUG-1 — Degenerate routing-rule values poison every apply** (`config_gen.py:199-221`). A user typing `*.`, `.`, or `*.*` emits `DOMAIN-SUFFIX,,PROXY`; `mihomo -t` rejects the whole file and *every* subsequent apply silently no-ops. Core-flow breakage from one bad rule.
3. **INSTALL-1 — `install.sh` destroys its own source at `/opt/pihy2`** (`install.sh:32-41`). Cloning into the natural install dir and running the installer `rm -rf`s the package and cannot recover. Irreversible.
4. **STORE-1 / STORE-2 — Corrupt `state.json` resets config and clobbers its own backup** (`store.py:98-110`, `129-140`). The M8 "back up and refuse to overwrite" claim is not honored: a single transient read/parse error silently wipes nodes + WebUI password + secret, and a second event overwrites the only `.bad` backup.
5. **DC-1 — Live node-switch selects the WRONG node** (`webui.py:368-381`). When two nodes share a base name, clicking node B silently routes traffic through node A because dedup naming depends on active-first ordering that diverges from the applied config.
6. **CONFLICT-1 — Existing user mihomo config silently destroyed** (`manager.py:208-212, 298-306`). pihy2 deliberately keeps a pre-existing mihomo binary but then overwrites `/etc/mihomo/config.yaml` with no backup.

### Notable strengths

After four prior hardening rounds, the codebase shows genuinely strong defensive engineering, and this audit confirmed several controls work as intended:

- **SSRF / DNS-rebinding defense** on the *fetch* paths is solid: `fetch_text`/`_download_to_file` pin to a validated public IP, re-validate every redirect hop, and reject private/loopback/reserved targets. The pinned-IP + per-redirect SSRF guard correctly defeats network MITM and rebinding.
- **Atomic writes** (`os.replace` for both `state.json` and `config.yaml`) mean no half-written files even under the concurrency race (ROBUST-3).
- **`config_gen._safe_int`** correctly guards `math.isfinite` (the parser side just didn't inherit it — ROBUST-5).
- **The WebUI `/api/settings` handler** is carefully written: key allowlist that discards `secret`, loopback-only `external_controller`, https-only mirror, CIDR/enum validation, string-bool coercion. The recurring complaint is that this rigor lives *only* there — but the rigor itself is real.
- **Apply/rollback safety on the restart path**: `apply_config` correctly refuses to enable IP forwarding when mihomo failed to come up (the gateway "naked traffic" guard). The `--no-restart` path is the one gap (BUG-9).
- **The hand-rolled YAML serializer always quotes scalars via `json.dumps`**, so the M3 value-injection class is genuinely closed (the remaining YAML findings are all on the *reader*, and on folded/block-scalar edges).
- **0600 permissions, file locking, login lockout, token expiry** are all present and behaviorally correct (the gap is test coverage, not correctness — TEST-1).

### Coverage / methodology

Audited subsystems: `parser.py`, `yaml_lite.py`, `config_gen.py`, `store.py`, `manager.py`, `webui.py`, `wizard.py`, `__main__.py`, `web/{app.js,index.html,style.css}`, `install.sh`, `tests/`. Dimensions: security/SSRF, bug/logic, robustness, data-contract, host-conflict, compatibility, feature-completeness, test-gap, style. Each finding was produced by a dimension-specialist finder, then cross-checked against the *current* source by 1–2 independent skeptics; verifier corrections (severity adjustments, scope narrowing, impact corrections) are preserved inline below. Two items remain **uncertain** and are flagged as such. `relation_to_prior` distinguishes genuinely new defects from incomplete/regressed prior fixes vs. gaps the prior rounds missed.

---

## Critical

*None. No remotely-triggerable root compromise or unconditional data-destruction was confirmed this round.*

---

## High

### SEC-1 — Non-ASCII WebUI password permanently bricks login
- **File:** `pihy2/webui.py:321` · **Dimension:** bug/security · **Verified:** confirmed (2/0) · **Relation:** new
- **What's wrong:** Login does `secrets.compare_digest(str(body.get("password","")), pw)`. `compare_digest` raises `TypeError: comparing strings with non-ASCII characters is not supported` if *either* operand has a non-ASCII char. Passwords are accepted verbatim by `/api/webui` (`webui.py:539`) and `wizard.py:183` with no ASCII restriction. The exception propagates out of `do_POST` inside the `with _lock:` block — uncaught — so login can never succeed.
- **Impact:** On a fully Chinese-language tool, a Chinese (or any non-ASCII) password locks the admin out of the root-privileged panel *permanently*. Only hand-editing `/etc/pihy2/state.json` restores access.
- **Repro:** `python3 -c "import secrets; secrets.compare_digest('密码123','密码123')"` → `TypeError`.
- **Fix:** Compare bytes: `secrets.compare_digest(str(body.get('password','')).encode('utf-8'), str(pw).encode('utf-8'))`. Apply the same `.encode()` anywhere passwords are compared.

### BUG-1 — Degenerate routing-rule values poison every config apply
- **File:** `pihy2/config_gen.py:199-209 (classify_rule), 212-221 (rule_to_mihomo), 525-534 (build_config)` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `classify_rule` strips wildcard/dot prefixes without re-validating the residue. `'*.'`/`'.'` → `('DOMAIN-SUFFIX','')`; `'*.*'` → `('DOMAIN-SUFFIX','*')`. `rule_to_mihomo` then emits `DOMAIN-SUFFIX,,PROXY` / `DOMAIN-SUFFIX,*,PROXY` and does **not** raise, so `build_config`'s per-rule `try/except` never fires, and its empty-value pre-filter doesn't catch it (the *original* value was non-empty). The empty-payload cases (`*.`, `.`) are the definitive crash; `*.*` is less certain to be rejected by mihomo.
- **Impact:** One accidentally-typed rule poisons the whole `config.yaml`. `apply_config` runs `mihomo -t` on the entire file (`manager.py:478`), which rejects the malformed line, so `apply_config` returns "配置校验失败，已保留原配置" and writes nothing — **every** later legitimate change is blocked until the user finds the one bad rule, with no pointer to it.
- **Fix:** After stripping prefixes in `classify_rule`, raise `ValueError` when the residue is empty or (for DOMAIN/DOMAIN-SUFFIX) still contains `*`/`?`, mirroring the IP-CIDR guard at line 187. This turns "one bad rule kills the apply" into "one bad rule is silently skipped."

### STORE-1 — Corrupt `state.json` is silently reset and the `.bad` backup is overwritten (M8 fix incomplete)
- **File:** `pihy2/store.py:98-110` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** CODE_REVIEW M8 claims "备份为 `state.json.bad` 并拒绝自动覆盖" (back up **and** refuse to auto-overwrite). The code only renames the corrupt file via `os.replace(path, path + ".bad")` and returns an empty `_new_state()`; it does **not** refuse subsequent saves. The next `save()` (any WebUI write, the timer, `pihy2 apply`) writes the empty state over the now-missing file — nodes, subscriptions, **WebUI password, and clash secret are gone with no log/UI warning.** Worse, `os.replace(...'.bad')` overwrites any pre-existing `.bad`, so a second corruption event destroys the only salvageable backup.
- **Impact:** A single transient read error / partial external write / bad hand-edit silently wipes the entire config and the auth credentials, with no in-tool way to notice or recover; repeat incidents clobber the backup. (pihy2's own writes are atomic, so the realistic trigger is external IO fault or a manual edit — narrow trigger, total blast radius.)
- **Fix:** (1) Non-destructive backup name (`state.json.bad.<timestamp>`, or refuse to overwrite an existing `.bad`). (2) Honor the contract: set an in-memory "degraded" flag and have `save()` refuse to overwrite until cleared, and emit a prominent journal/stderr warning + surface it in `/api/status`. (3) Distinguish `FileNotFoundError` (legit fresh install) from `JSONDecodeError`/`OSError` (corruption) — a transient `OSError` on open arguably should retry/abort, not wipe.

### DC-1 — Live node-switch / delay probe selects the WRONG node when base names collide
- **File:** `pihy2/webui.py:368-381 (/api/active), 253-265 (/api/delays)` · **Dimension:** data-contract · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** `/api/active` computes the clash target via `display_names(store.nodes_active_first()).get(nid)` and calls `clash_select("PROXY", disp, ...)` **without re-rendering/applying** the config. `display_names` → `_dedup_names`, whose `#2/#3` suffixes depend on input order. `nodes_active_first()` re-sorts the clicked node to the front, so suffix assignment diverges from the order used at the last apply. The running mihomo config has a *fixed* name→node map. Concrete: two nodes both named `JP` (n1,n2), applied active=n1 → live `["JP"(n1), "JP #2"(n2)]`. Click n2 → `display_names([n2,n1]) = {n2:"JP", n1:"JP #2"}` → backend selects live proxy `"JP"` = **n1, not n2**. `/api/delays` mis-attributes latency the same way.
- **Impact:** With duplicate base names (the norm for airport subscriptions), clicking node B silently routes traffic through node A and the latency table maps to wrong nodes — `r.live=true`, no error. Gated on ≥2 nodes deduping to the same base name **and** current active differing from apply-time active.
- **Fix:** Make the proxy name map independent of active ordering: number nodes by a stable key (node id / raw `data["nodes"]` order) in `_dedup_names`, used identically in `build_config` *and* in `display_names`→`clash_select`/`clash_delay`. Keep active-first ordering only for the selector default list. (Alternative: regenerate+apply inside `/api/active` before the live select.)

### CONFLICT-1 — Existing user-managed `/etc/mihomo/config.yaml` silently overwritten, no backup
- **File:** `pihy2/manager.py:208-212, 298-306, 482` · **Dimension:** conflict · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `install_mihomo()` returns "existing" and skips download when a working mihomo binary is already present (lines 208-211) — explicitly designed to coexist. But `apply_config()` → `write_config()` then `os.replace()`s `MIHOMO_CONFIG = "/etc/mihomo/config.yaml"` (the canonical path) with pihy2's render, with no existence check and no `.bak`. A user already running mihomo from that path loses their hand-tuned config (rules/providers/DNS) entirely on first install/apply.
- **Impact:** Irreversible destruction of a user's hand-managed mihomo config. Combined with CONFLICT-2 (unit overwrite + restart) their working proxy is replaced wholesale on what looks like an additive install. (Borderline-medium: the artifact is regenerable and pihy2 is take-over tooling — but the loss is silent and irreversible, in direct tension with the deliberate "coexist" branch.)
- **Fix:** On first write, if `MIHOMO_CONFIG` exists and lacks pihy2's generated-by header (`config_gen.py:549`), copy to `config.yaml.pihy2-bak` (or refuse + warn) before `os.replace`. The header lets repeated pihy2 applies skip the backup.

### INSTALL-1 — `install.sh` destroys its own source when checked out at `/opt/pihy2`
- **File:** `install.sh:32-41` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `SRC_DIR` comes from `BASH_SOURCE`; `INSTALL_DIR` is hard-coded `/opt/pihy2`. Line 37 unconditionally `rm -rf "$INSTALL_DIR/pihy2" "$INSTALL_DIR/web"` **before** the copy loop. If the user clones/extracts into `/opt/pihy2` (a natural choice, since the tool installs there) and runs `sudo bash install.sh`, then `SRC_DIR == INSTALL_DIR`: line 37 deletes the source package, the copy loop finds nothing (`[ -e "$SRC_DIR/pihy2" ]` now false), and `cp -r README.md` onto itself errors under `set -e`, aborting.
- **Impact:** The installer deletes the program's own code and leaves a broken install (`python3 -m pihy2` → `No module named pihy2`). Re-running can't recover. Destruction of the user's checkout (re-clonable, hence high not critical).
- **Fix:** Guard the destructive step and copy: `if [ "$SRC_DIR" != "$INSTALL_DIR" ]; then rm -rf ...; cp ...; fi` (compare canonicalized paths); when equal, skip the copy and go straight to creating the wrapper + running the wizard.

### COMPAT-1 — `detect_arch()` maps armv6 to the armv7 asset → SIGILL on Pi Zero / Pi 1
- **File:** `pihy2/manager.py:68-77` · **Dimension:** compatibility · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `detect_arch()` collapses all 32-bit ARM into `armv7`: `if m.startswith("armv7") or m.startswith("armv6") or m == "armhf": return "armv7"`. The mihomo release ships **separate** `mihomo-linux-armv6-*.gz` and `armv7-*.gz` assets (verified against the GitHub release API). An armv6 device (`platform.machine() == 'armv6l'`: Pi Zero/Zero W/Pi 1) is handed the armv7 binary.
- **Impact:** The armv7 binary uses ARMv7-only instructions absent on the ARMv6 core → `Illegal instruction` (SIGILL). `_binary_ok`'s `-v` check fails, install aborts with "downloaded binary cannot run", and the entire armv6 Pi family can never deploy despite a correct published asset. (Scope: armv6 only; arm64/armv7 unaffected.)
- **Fix:** Add a distinct branch **before** the armv7 line: `if m.startswith("armv6"): return "armv6"`; keep `armhf`→`armv7` (Debian armhf == armv7 baseline). Then `resolve_download_url`/`fallback_url` request the armv6 asset. Also add an `armv6` `PINNED_SHA256` entry, else the mirror path rejects it at line 218 (same gap M10 notes for armv7).

### SEC-2 — Non-pinned "latest" mihomo binary installed as root with NO SHA-256 check
- **File:** `pihy2/manager.py:224-281` (gate at 246, log at 253) · **Dimension:** security · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** On the default first-install path (no mirror), `install_mihomo()` resolves the *latest* release and downloads it. SHA-256 verification is gated on `if ver == PINNED_VERSION and arch in PINNED_SHA256`; for the latest tag `ver != PINNED_VERSION`, so the check is skipped and the code logs "该下载未做 SHA-256 比对". The only gates are TLS and `mihomo -v`. CODE_REVIEW M12 marks this "计划内" (planned) — identified but not fixed for the default path.
- **Impact:** Supply-chain / root-RCE: a tampered/hijacked latest-release asset or a CDN object that defeats only-TLS yields arbitrary code run as root. The integrity anchor (`PINNED_SHA256`) exists but is bypassed for exactly the common flow. **Threat-model caveat (verifier):** the pinned-IP TLS + per-redirect SSRF guard already defeat on-path MITM/rebinding, so exploitation requires compromise of the GitHub release asset / its CDN origin, or a TLS-breaking CA compromise — not an ordinary on-path attacker. High is justified by root execution + the half-applied integrity mechanism; a reviewer could reasonably call it medium.
- **Fix:** Default the install to `fallback_url()`/`PINNED_VERSION` (which *is* SHA-256-verified) and only follow `resolve_download_url('latest')` on explicit operator opt-in; even then, fetch and verify the release's checksums over the same pinned-IP TLS channel and refuse install if no verified checksum is obtained. (Do not assume per-asset hashes are always published.) *(Note: BUG-13, the duplicate latest/armv7-fallback finding, is folded here; it was rated **uncertain** by one verifier who considers the non-checksummed default the accepted resolution of M10/M12 — see Info.)*

---

## Medium

### STORE-2 — Corrupt/edited `state.json` with non-dict `settings`/`webui` hard-crashes every entrypoint
- **File:** `pihy2/store.py:129-140` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** `_migrate` spreads `{**config_gen.DEFAULT_SETTINGS, **data.get("settings", {})}` and `{**_new_state()["webui"], **data.get("webui", {})}`. If either key is present but not a dict (string/list/int), `{**non_dict}` raises `TypeError: 'X' object is not a mapping`. The prior round hardened `nodes`/`subscriptions` (non-dict filtering) but not the `settings`/`webui` containers. `load()` only catches `JSONDecodeError`/`OSError`, so the `TypeError` escapes uncaught and the `.bad` backup never runs.
- **Impact:** A single malformed `state.json` makes the *entire* tool unloadable — every CLI command, the WebUI service, and the timer crash on `Store()` construction, with no auto-backup. The operator is locked out and can't even use the WebUI to fix it.
- **Repro:** `echo '{"version":1,"settings":"pwned"}' > state.json; python3 -c 'from pihy2.store import Store; Store()'` → `TypeError` at `store.py:137`.
- **Fix:** Coerce before spreading: `_s = data.get("settings"); _s = _s if isinstance(_s, dict) else {}` (and same for `webui`). Broaden `load()`'s except to also catch `TypeError`/`ValueError` so structurally-corrupt state is `.bad`-backed-up and reset rather than crashing every entrypoint.

### STORE-3 — Non-string `secret` survives migration and crashes `/api/config` redaction + clash client
- **File:** `pihy2/store.py:138-139` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `_migrate` only checks truthiness: `if not base["settings"].get("secret"): ... token_hex(16)`. A truthy non-string (e.g. a list/number) is kept verbatim. Downstream assumes `str`: `/api/config` does `cfg.replace(sec, "******")` (`webui.py:292`), `_clash_request` does `"Bearer " + settings["secret"]` (`manager.py:759`) — both raise `TypeError`. `build_config` also serializes it into mihomo's `secret:` field.
- **Impact:** `state.json` with `"secret":["x"]` makes `/api/config` 500 and every clash-API call (switch/delay/traffic/close) throw; the redaction crash could leak internals in a traceback.
- **Fix:** `sec = base["settings"].get("secret"); base["settings"]["secret"] = sec if isinstance(sec, str) and sec else secrets.token_hex(16)`.

### DC-2 — A non-string node `name` crashes the entire config render / apply path
- **File:** `pihy2/config_gen.py:408-424, 428-431` · **Dimension:** data-contract · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `_dedup_names` does `base = (n.get("name") or n.get("server") or "节点").strip()`. A truthy non-string `name` (int `2024`, list) makes `.strip()` raise `AttributeError`. `build_config` calls `_dedup_names` **before** the per-node `try/except`, so the crash propagates out of `render`/`render_config` → `/api/config`, `/api/apply`, and the timer apply. `PUT /api/nodes/<id>` and `POST /api/nodes` persist the raw JSON body with no coercion, so `{"name": 2024}` is stored.
- **Impact:** One numeric/list name makes config generation throw for *all* nodes; preview, apply, and the periodic timer apply all 500/crash with an opaque `AttributeError` until hand-edited. (Auth-gated, frontend always sends strings — so self-inflicted-by-API or externally-edited, hence medium.)
- **Fix:** Coerce at the single choke point: `base = (str(n.get("name") or n.get("server") or "节点")).strip() or "节点"` (covers `build_config` and `display_names`). Defensively `str()` name/server in builders and stringify name/server/uuid/password in `update_node`/`add_node`.

### DC-3 — Malformed `/api/rules` body persisted unvalidated, poisoning `state.json` so every later render/apply 500s
- **File:** `pihy2/webui.py:455-458, 362-365` · **Dimension:** data-contract · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `PUT /api/rules` does `store.set_rules(body.get("rules", []))` verbatim. If `rules` contains a non-dict element (e.g. `["foo"]`), `build_config` line 527 `rv = r.get("value")` runs **outside** the per-item `try` (line 530) and raises `AttributeError`. Because the bad value is saved, it's a poison pill: every later `/api/config` and `/api/apply` (`store.render_config()`, no try/except) then 500s until `state.json` is hand-edited. *(Verifier scope: the `/api/nodes` POST case does NOT persist — `add_node`'s `dict(node)` raises before append, so it's a transient 500 only. Also the rule loop is gated by `if nodes:`, so it manifests once ≥1 node exists. Severity downgraded high→medium: write requires `_guard_write` + `_authed`, and re-saving rules via the UI overwrites the poison.)*
- **Impact:** A malformed authenticated write corrupts `state.json` so config preview and apply (incl. the timer) break until repair.
- **Fix:** At the REST boundary, `rules = [r for r in body.get("rules", []) if isinstance(r, dict)]`. **Also** defensively guard `config_gen.py:527` (move `rv = r.get("value")` inside the `try`, or `if not isinstance(r, dict): continue`) so a previously-poisoned (or externally hand-edited) state can still render.

### DC-4 — `update_node` lets a manual PUT rewrite the `sub` field, corrupting subscription membership
- **File:** `pihy2/store.py:177-182` (via `webui.py:448-454`) · **Dimension:** data-contract · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `update_node` filters only `id`: `n.update({k: v for k, v in fields.items() if k != "id"})`. The PUT passes the whole body. Setting `sub` re-tags a manual node into a subscription (then silently deleted on the next `set_subscription_nodes` refresh, `store.py:239`), or clearing `sub` makes a real sub node linger forever. The frontend never sends `sub`, but the API accepts and persists it. *(This dedups two separately-reported findings — the security-framed and data-contract-framed versions of the same root issue. Verifier corrected the overstated impact: arbitrary injected keys do **not** flow into the generated mihomo config — the builders read only known fields — so the real harm is ownership corruption, not config injection.)*
- **Impact:** A crafted/buggy PUT silently moves nodes between subscriptions → nodes vanish on the next refresh or leak/duplicate.
- **Fix:** Restrict `update_node` to a whitelist of user-editable fields (mirror the `/api/settings` allowlist); at minimum `if k not in ("id", "sub")`.

### ROBUST-1 — A field value starting with `[`/`{` aborts the entire subscription import
- **File:** `pihy2/yaml_lite.py:63-66` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** In `_scalar`, any value whose first char is `[`/`{` is parsed as a flow collection; if malformed, `_parse_flow` raises `YamlError`, which `parse_clash_yaml` catches at the *document* level and returns `([], [error])` — **all** nodes lost, not just the offending one. Unlike the per-proxy `try/except`, a parse-time scalar error in one field kills the whole document.
- **Impact:** One unquoted password/name beginning with `[`/`{` (or a truncated flow list) anywhere in a multi-hundred-node sub discards every node. Denial-of-availability for the whole import from one untrusted line.
- **Fix:** Make flow-scalar errors non-fatal per field: in `_scalar`, on `YamlError` from the flow branch fall back to the raw string; or only treat a value as flow when it actually ends with the matching `]`/`}`.

### BUG-2 — Merge key with flow-list of aliases (`<<: [*a, *b]`) silently drops all merged keys
- **File:** `pihy2/yaml_lite.py:120-154, 210-218, 270-292` · **Dimension:** bug · **Verified:** confirmed (2/0), severity high→medium · **Relation:** prior-fix-incomplete
- **What's wrong:** Aliases are only resolved by `_resolve_scalar` (block context). Inside a flow collection, `_scalar('[*a]')` → `['*a']` (literal strings). For `<<: [*a, *b]` (a common idiom, explicitly advertised in the module docstring), `_assign` iterates `merges=['*a','*b']`, finds neither is a dict, and skips both — the merged mapping is silently lost.
- **Impact:** Aggregated subscriptions that factor shared proxy settings into anchors applied via `<<: [*common, *tls]` import proxies missing those keys; `proxy_to_node` then raises ParseError (node skipped, `parser.py:537-538`) or builds a broken node. Affected proxies vanish. (Downgraded from high: degrades gracefully with a visible error string; single-alias `<<: *a` works; the dominant PyYAML-dump export format has no anchors.)
- **Fix:** Resolve aliases inside flow collections: in `_assign`, before the dict check, resolve any `str` element of the form `*name` via `self.anchors`; or make `_resolve_scalar` recurse into list/dict results and replace `*name` with `self.anchors[name]`.

### BUG-3 — Anchor on a block-sequence item (`- &name` then indented mapping) crashes the whole document
- **File:** `pihy2/yaml_lite.py:295-343` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `_seq` strips the dash; `_split_kv('&n1')` → `('&n1', None)`, so the `v is None` branch treats it as a plain scalar (`_resolve_scalar('&n1')` sets `anchors['n1']=None`, appends `None`, advances one line). The following more-indented `name: a` then hits the `ind > indent` guard up the stack → `YamlError('缩进异常')`. No handling for an anchor introducing a block-mapping seq item.
- **Impact:** A sub using the legal `- &anchor` form (aggregated/hand-written Clash configs that anchor whole proxy entries) fails to parse *entirely* — `parse_clash_yaml` returns `([], [error])`, losing every node.
- **Fix:** In `_seq`, detect `rest.startswith('&') and len(rest.split())==1`: record the anchor, advance one line, and if the next line is more-indented parse it via `_block(next_indent)`, store under the anchor, append it. Also handle `- &n scalar`.

### BUG-4 — Clearing TUN DNS hijack does nothing — `config_gen` forces `any:53` back, and the warning is suppressed
- **File:** `pihy2/config_gen.py:478-484` (interacts with `manager.py:695-707`, `webui.py:496-498`) · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `render` does `hijack = s.get("tun_dns_hijack"); if not isinstance(hijack, list) or not hijack: hijack = ["any:53"]`. An empty list is falsy → `["any:53"]` is written anyway. Meanwhile `dns_conflict_warning` returns `""` for an empty list. So the remediation the warning itself recommends ("把『TUN DNS 劫持』改为仅 TUN 接口或清空") does not work when the user *clears* it: warning gone, but mihomo still hijacks `any:53`.
- **Impact:** The user believes they stopped hijacking `:53` (no warning) but mihomo still does, breaking a coexisting Pi-hole/dnsmasq/systemd-resolved. Behavior and warning contradict each other. (Only the "clear" remediation is broken; "TUN-only" still works.)
- **Fix:** Distinguish missing/default from explicitly-emptied: `hijack = s.get("tun_dns_hijack"); if hijack is None or not isinstance(hijack, list): hijack = ["any:53"]` (drop the `not hijack` check); emit `dns-hijack: []` when cleared. `dns_conflict_warning` already agrees.

### BUG-5 — TUIC `skip_cert_verify` silently lost on export round-trip (key mismatch)
- **File:** `pihy2/parser.py:350-359, 596-602` (also cited 358 / 609-610) · **Dimension:** bug/data-contract · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `node_to_link` exports the insecure flag as `allowInsecure=1` (shared vless/trojan/tuic block). vless/trojan parsers read `allowInsecure`, so they round-trip. But `_parse_tuic` reads only `_first(qs, "allow_insecure", "insecure")` — never the camelCase `allowInsecure` its own exporter emits. *(Deduplicated: this was independently reported three times by the parser, bug, and feature finders.)*
- **Impact:** A TUIC node with skip-cert-verify (common for self-signed servers) loses the flag on export+re-import via the WebUI copy-link feature; mihomo then enforces cert verification and the node stops connecting. Silent loss of a security-relevant field.
- **Repro:** `parse_link("tuic://uu:pw@u.com:443?insecure=1#U")["skip_cert_verify"]` is `True`; after `node_to_link`+re-parse it's `False`.
- **Fix:** Add the key to the TUIC parser: `_first(qs, "allow_insecure", "allowInsecure", "insecure", default="0")` (case-insensitive `_first` makes lowercase sufficient). Optionally normalize the exporter to emit `insecure`.

### BUG-6 — vmess `node_to_link` drops `skip_cert_verify` entirely
- **File:** `pihy2/parser.py:560-576` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `_parse_vmess` reads `skip-cert-verify`/`verify_cert` (line 244) and `config_gen._proxy_vmess` consumes `node["skip_cert_verify"]`, but the vmess export dict `j` never includes a `skip-cert-verify` field, so export+re-import always yields `False`.
- **Impact:** A vmess node with skip-cert-verify loses it on copy-link round-trip → mihomo enforces cert verification → self-signed vmess server stops connecting. (Fails "safe" — not a security downgrade — but silently breaks connectivity.)
- **Fix:** In the export dict (~line 572) add conditionally (matching the alpn pattern): `if node.get("skip_cert_verify"): j["skip-cert-verify"] = True`. The parser already accepts the key.

### BUG-7 — Unsupported transports (kcp/mkcp) silently fall through to a tcp config that can never connect
- **File:** `pihy2/parser.py:135-150, 485-491` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `_net_fields` explicitly rejects h2/http/quic/xhttp to avoid emitting a half-config, but `kcp`/`mkcp` (and any other unlisted value) are neither rejected nor handled — `node["network"]` is never set, so `config_gen` produces a proxy with no `network` → mihomo defaults to tcp. The same gap exists in `proxy_to_node` (the net guard at line 488 lists only h2/http/quic/xhttp).
- **Impact:** A vmess/vless node using mKCP imports without error, passes `mihomo -t`, but connects over plain TCP to an mKCP server — the node simply never works, no error surfaced. Contradicts the module's stated fail-loudly design.
- **Fix:** In `_net_fields`, after the known transports, raise `ParseError` for any remaining non-tcp value; mirror the check in `proxy_to_node`.

### BUG-8 — Subscription add reports success even when fetch/parse fully fails
- **File:** `web/app.js:86-93` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** new
- **What's wrong:** `addSub()` treats any `r.ok` as success and toasts "订阅已添加，${r.count||0} 个节点已生效". But `/api/subs` **always** returns `{ok:true, count, errors}` — even when `fetch_sub_nodes` returns `([], errs)` (bad URL, SSRF block, non-200, decompression/parse failure). `count==0` and the real reason in `r.errors` is never read; the sub row is persisted before the fetch.
- **Impact:** Users can't distinguish a working sub from a broken one; failures look like success, an empty sub stays in `state.json` and its timer keeps re-fetching nothing.
- **Fix:** Gate the success toast on `r.count`: `if (r.ok && r.count) toast(...,'ok'); else toast('订阅已添加但未解析到节点：' + ((r.errors||[]).slice(0,2).join('; ') || '请检查链接或格式'), 'err')`. Optionally don't persist a 0-node sub server-side.

### BUG-9 — `apply` with `restart=False` enables gateway IP-forward/rp_filter without confirming mihomo is running
- **File:** `pihy2/manager.py:483-492` · **Dimension:** robustness · **Verified:** confirmed (1/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** `apply_config` gates the `set_ip_forward(gw)` side effect on mihomo being active — but only on the restart path. With `restart=False`, the `if restart and ...` block is skipped, `started` stays `True`, and line 492 calls `set_ip_forward(gw)` unconditionally, turning on `ip_forward=1`/`rp_filter=2` even though mihomo wasn't (re)started. Reachable from `pihy2 apply --no-restart` and from the wizard (`apply_config(store, restart=False)` at `wizard.py:207`, before `enable_start` at 216).
- **Impact:** In gateway mode, IP forwarding can be enabled while no live proxy exists — defeating the exact guard the code's own comment (line 489) describes. Downstream LAN devices' traffic is forwarded through a dead/black-holed proxy until mihomo is independently started.
- **Fix:** When `restart` is False, only call `set_ip_forward(gw)` after confirming mihomo is active (`wait_active('mihomo')` / is-active check), regardless of the restart flag.

### CONFLICT-2 — Install overwrites an existing host `mihomo.service` with no detection or backup
- **File:** `pihy2/manager.py:344-360, 388` · **Dimension:** conflict · **Verified:** confirmed (2/0), severity high→medium · **Relation:** prior-missed
- **What's wrong:** `install_services()` unconditionally `_write()`s `/etc/systemd/system/mihomo.service` with pihy2's unit body, then daemon-reloads — no `os.path.exists`, no `is-active mihomo` probe, no backup. The wizard then `enable_start("mihomo")` restarts it under pihy2's `ExecStart {MIHOMO_BIN} -d {MIHOMO_DIR}`. Uninstall `os.remove`s the unit, so a host that had the upstream `mihomo.service` ends up with none.
- **Impact:** A user running the standard `mihomo.service` has their unit silently replaced and daemon restarted against a pihy2 config; uninstall then leaves no `mihomo.service` at all, original unrecoverable. (Conditional on the host already running mihomo under that name → medium.)
- **Fix:** Detect a pre-existing unit (`systemctl is-active mihomo` / file exists with non-pihy2 content), back it up (`mihomo.service.pihy2-bak`), and refuse/prompt. Better: namespace pihy2's unit (`pihy2-mihomo.service`) so it never collides; on uninstall only remove units pihy2 created (detect via a `Description=mihomo (pihy2)` marker).

### CONFLICT-3 — No detection of a pre-existing TUN/VPN; auto-route + auto-redirect collide with the default-route owner
- **File:** `pihy2/config_gen.py:481-488` · **Dimension:** conflict · **Verified:** confirmed (2/0), severity high→medium · **Relation:** prior-missed
- **What's wrong:** `build_config` always emits `tun.enable=true` with `auto-route:true`, `auto-redirect:true` (nftables), `auto-detect-interface:true`, no fixed `device`. On a host already running WireGuard/OpenVPN/tailscale/another mihomo, two auto-route TUNs both claim the default route and pihy2's nft redirect layers on the existing rules → non-deterministic routing/blackholes. `dns_conflict_warning` only checks `:53` resolvers, never an existing tun/wg interface or a second clash.
- **Impact:** Bringing up pihy2 on a host with an existing VPN/TUN can hijack/break the existing tunnel's routing and host connectivity with no warning. (Conditional precondition → medium; `auto-detect-interface` and the user-toggleable `tun_auto_redirect` partly mitigate.)
- **Fix:** Before apply, enumerate `ip -o link` for `tun*/wg*/utun*/tailscale*`/another clash and detect a non-pihy2 default-route owner, then warn (mirroring `dns_conflict_warning`) and surface it from `apply_config`. Consider a fixed `tun.device` name and honoring `tun_auto_redirect=false` when another tunnel is present.

### CONFLICT-4 — WebUI/controller/proxy port collisions undetected; `pihy2-web` crash-loops on bind failure
- **File:** `pihy2/webui.py:587-593` · **Dimension:** conflict · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `serve()` does `httpd = server_cls((bind, port), Handler)` with no `try/except`. If port 8088 (or chosen port) is taken, the constructor raises `OSError`; with the unit's `Restart=on-failure`/`RestartSec=5`, `pihy2-web` crash-loops forever with no actionable message. The controller (9090) and mixed-port (7890) collisions surface only via mihomo failing to start; the WebUI port is never pre-flighted.
- **Impact:** On a host where 8088/7890/9090 are in use, install appears to succeed but the panel never comes up (silent crash-loop) or mihomo refuses to start, the clue buried in journalctl.
- **Fix:** Wrap the bind in `try/except OSError`, log a clear "port N already in use" message, and exit in a way that doesn't just re-trigger the restart loop. In the wizard, pre-flight the WebUI port + mixed-port (7890) + controller (9090) + DNS (1053) via trial bind / `ss -ltn` and warn before installing.

### CONFLICT-5 — `dns_conflict_warning` is advisory-only and invisible on timer-driven applies
- **File:** `pihy2/manager.py:474-475, 690-707` · **Dimension:** conflict · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** `apply_config` logs the warning but proceeds. With default `tun_dns_hijack=["any:53"]` + auto-route, mihomo hijacks all `:53`, intercepting systemd-resolved (the RPi OS/Ubuntu default) or Pi-hole. When apply runs from the timer (`pihy2 sub update all --apply`), the warning goes only to the journal where no human sees it.
- **Impact:** On the common Pi target, the default config intercepts the host's DNS; a Pi-hole user's ad-blocking stops, and the "fix" is buried in a log line a timer apply never shows. *(Verifier framing: DNS interception is the intended purpose of `any:53` in TUN mode — the defect is that a detected conflict is advisory-only and invisible on timer applies, not that hijacking is itself a bug.)*
- **Fix:** Persist the warning into status/WebUI so timer applies surface it, and/or add a one-time wizard confirm when a `:53` service is active. Do **not** auto-change `tun_dns_hijack` silently (that would break the proxy's own DNS routing).

### TEST-2 — Settings write-path whitelist + external_controller/mirror/CIDR validation untested
- **File:** `tests/test_basic.py:459-515` · **Dimension:** test-gap · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** The dense security-relevant validation in `PUT /api/settings` (secret-discarding allowlist, loopback-only `external_controller`, https-only mirror, `fake_ip_range` CIDR, `tun_stack`/`log_level` enums, string-bool coercion for gateway_mode/allow_lan/ipv6) has **no** unit test. The bool coercion is safety-relevant: without it, the string `"false"` would enable gateway mode and IP forwarding.
- **Impact:** Regressions (re-allowing `secret`, dropping the loopback check, breaking the bool coercion so `"false"` turns on the gateway) would pass the suite.
- **Fix:** Factor the sanitization block into a pure `sanitize_settings(body)` helper and unit-test: `secret` dropped, non-loopback controller rejected, non-https mirror rejected, bad CIDR rejected, `gateway_mode="false"` → `False`.

### TEST-1 — WebUI auth/CSRF/rebinding guard logic has zero behavioral tests
- **File:** `tests/test_basic.py:488-497` · **Dimension:** test-gap · **Verified:** confirmed (2/0), severity high→medium · **Relation:** prior-missed
- **What's wrong:** Only `_valid_listen_port`/`_valid_bind` are covered. None of `_guard_write` (Origin same-origin + no-password Host-must-be-IP/localhost), `_authed`/token validation, the login lockout counter, `_sweep_locked` expiry, or `_body` JSON normalization is exercised. These are exactly the H2/H4/M13 fixes CODE_REVIEW claims fixed. *(The current guard code is correct — this is a regression-protection gap, hence medium not high.)*
- **Impact:** A future edit flipping the Origin comparison, dropping the no-password Host check, or breaking the lockout would pass all 168 tests — the invariants gating root-level config writes on a network-exposed panel are unprotected against regression.
- **Fix:** Instantiate `Handler` via `Handler.__new__(Handler)`, set stub `headers`/`client_address`/`rfile`/`wfile`, monkeypatch `_store()`, and assert: Origin mismatch → 403; no-password domain-name Host rejected but IP/localhost accepted; `_authed` rejects missing/expired/unknown tokens; `LOGIN_MAX_FAILS` failures → 429; `_body` returns `{}` for non-dict/oversized/bad-Content-Length.

### TEST-3 — `apply_config` deploy/rollback flow (the tool's core function) is untested
- **File:** `tests/test_basic.py:371-411` · **Dimension:** test-gap · **Verified:** confirmed (2/0), severity high→medium · **Relation:** prior-missed
- **What's wrong:** Manager tests cover SSRF/`_apply_mirror`/`test_config`/`set_ip_forward` but never `apply_config` (`manager.py:458-493`), whose safety invariants are: (a) on `test_config` fail, don't write config or touch forwarding; (b) `text==current` → skip restart but still `set_ip_forward(gw)`; (c) if mihomo fails to come up, don't enable forwarding. All are monkeypatchable like the existing `set_ip_forward` test. *(Current code is correct → regression gap → medium.)*
- **Impact:** A regression moving `set_ip_forward(gw)` before the started-check, or writing config before validation, ships silently — in gateway mode a connectivity/security failure.
- **Fix:** Three tests using the lambda-capture pattern at lines 396-410: `test_config`→fail (assert `write_config`/`set_ip_forward` never called, returns False); success + `wait_active`→False (assert `set_ip_forward` never called); equal-config branch (assert restart skipped, `set_ip_forward` called).

### CLI-1 — Hand-edited/migrated subscriptions missing keys crash `pihy2 sub list` (KeyError)
- **File:** `pihy2/__main__.py:95-96` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `cmd_sub` list uses direct subscript access `s['id']`/`s['name']`/`s['count']`/`s['updated']`/`s['url']`. `Store._migrate` filters non-dict sub entries and backfills `_subseq`/`id` but does **not** backfill `name`/`url`/`count`/`updated`. A hand-edited/imported/old-version `state.json` (e.g. `[{"id":"s1","url":"..."}]`) lacks those keys → `KeyError`, command aborts. *(Verifier: the WebUI does **not** crash — it serializes raw dicts; the breakage is CLI-only.)*
- **Impact:** `pihy2 sub list` crashes for any sub entry missing a field; the user can't list/manage subs to fix the bad entry.
- **Fix:** In `_migrate`, normalize each sub dict: `s.setdefault('name','订阅'); s.setdefault('url',''); s.setdefault('count',0); s.setdefault('updated','')` and ensure an `id` (mirroring the node backfill at `store.py:147-149`; `get_subscription`/`delete_subscription` also do `s["id"]`).

### ROBUST-2 — Unhandled exceptions in REST handlers return opaque 500 with no error envelope
- **File:** `pihy2/webui.py:305-436, 439-549` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** Neither `_api_post`/`_api_put`/`_api_delete` wraps the handler body in `try/except`. Any unexpected exception (non-dict node → `add_node` raises `TypeError`, manager/parser error, render error from poisoned settings) propagates to `BaseHTTPRequestHandler` → bare 500 with no `{ok:false,error:...}` JSON the frontend expects. (Locks release cleanly, so no deadlock; the harm is an opaque break.) *(Verifier: `dict(5)` raises `TypeError`, not `ValueError` — outcome unchanged.)*
- **Impact:** Edge-case bad input / transient manager errors surface as opaque 500s; the frontend can't distinguish a validation problem from a server fault.
- **Fix:** Wrap the per-method dispatch in `try/except` returning `self._err(str(e), 400/500)` with a JSON body, or add input-type guards at each entry point.

### ROBUST-4 — Settings that pass WebUI validation but fail `mihomo -t` are persisted, wedging every future apply
- **File:** `pihy2/webui.py:459-508` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `/api/settings` validates that `dns_nameservers`/`dns_china`/`tun_dns_hijack` are *lists* but not their *contents*. `dns_nameservers=["this is not a dns server"]` passes, is persisted, and rendered verbatim into `config.yaml`'s `nameserver:` block; `mihomo -t` rejects it. `apply_config` keeps the old config (good) but the bad value stays in `state.json`, so every later apply — including the unattended timer — fails identically. `config_gen` only falls back on wrong *type*, not invalid content.
- **Impact:** One bad DNS/hijack entry typed in the panel silently breaks all future applies (manual + timer); subscription auto-updates stop taking effect, easy to misdiagnose as "subscriptions broken." (Self-inflicted by an authed admin → medium.)
- **Fix:** Validate each entry as IP / IP:port / DoH-DoT-DoQ URL (`https://`,`tls://`,`quic://`,`h3://`,`udp://`,`system://`,`dhcp://`) and reject the whole update on a bad entry; and/or drop non-parseable entries in `build_config`, falling back to defaults when the list empties.

### FEAT-1 — `tun_dns_hijack`/`tun_auto_redirect` have no WebUI control yet an error message points users to one
- **File:** `web/index.html:122-187` (settings pane); `config_gen.py:26-27,478-486`; `webui.py:496-500`; `manager.py:706` · **Dimension:** feature-completeness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** Both settings are wired in `config_gen` and accepted by `/api/settings`, and `DEFAULT_SETTINGS` comments describe them as user-changeable for Pi-hole/dnsmasq/Docker coexistence. But the Settings tab renders no input for either and `saveSettings()` never sends them. Worse, `dns_conflict_warning()` returns a message telling the user "可在设置里把「TUN DNS 劫持」改为仅 TUN 接口或清空" — pointing at a control that doesn't exist (and there's no CLI for it either).
- **Impact:** Users hitting the DNS-conflict warning (common: Pi running Pi-hole/dnsmasq/resolved) are instructed to fix it in 设置, but cannot — the only remediation is editing `state.json` or a raw API call. The Docker/firewalld auto-redirect escape hatch is likewise unreachable.
- **Fix:** Add a "TUN DNS 劫持" textarea (→ `tun_dns_hijack` list) and an "auto-redirect (nftables)" checkbox (`tun_auto_redirect`) to the TUN/DNS fieldset, include both in `saveSettings()`'s payload; or reword `manager.py:706` to stop referencing a non-existent control.

### FRONT-1 — Optimistic node reorder never reverted on server failure
- **File:** `web/app.js:192-201, 320-335` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** new
- **What's wrong:** `moveNode()` and the drag handler mutate `STATE.nodes` and `renderNodes()` **before** awaiting `POST /api/nodes/order`. `moveNode` toasts on `!r.ok` but doesn't restore order; the drag handler doesn't check `r.ok` at all. On failure (401 mid-session, validation, network) the visible order diverges from `state.json`; since order drives test/selection priority and active-first display, the next `loadState()` snaps nodes back silently, or a 401+re-login loses the reorder with a success-looking UI.
- **Impact:** Silent divergence between displayed and persisted order; the user believes a reorder saved when it didn't; the drag path gives zero failure feedback.
- **Fix:** Capture prior order; on `!r.ok` (or catch) call `loadState()`/re-render to restore server truth and toast the error. Make the drag handler check `r.ok` and wrap in `try/catch`.

### FRONT-2 — `updateAllSubs`/`updateSub` report success and "已生效" even when fetches/apply fail
- **File:** `web/app.js:94-104` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** new
- **What's wrong:** `done(r, '已更新 ${r.count||0} 个节点并生效')`. `/api/subs/update` returns `{ok:true, count, applied}` with `ok` always true and per-sub fetch errors discarded server-side. If all targeted subs fail, `count==0` and the UI still toasts green "已更新 0 个节点并生效"; "并生效" is misleading when `total==0` because `apply_config` is skipped.
- **Impact:** Failed refreshes look like successful no-op updates; "已生效" shown even though nothing applied.
- **Fix:** Branch on `r.count`: when 0, neutral/error toast ("未更新到新节点，请检查订阅链接是否可访问"); only include "并生效" when `applied` is non-empty. Optionally surface the discarded `_errs`.

---

## Low

### SEC-3 — CSRF/rebinding same-origin check ignores port (and scheme)
- **File:** `pihy2/webui.py:154-159` · **Dimension:** security · **Verified:** confirmed (2/0), reported medium → kept **low/medium**¹ · **Relation:** prior-fix-incomplete
- **What's wrong:** `_guard_write` compares only hostnames (`urlparse(origin).hostname` drops the port), and never the scheme. So `Origin: http://127.0.0.1:9999` is treated as same-origin as `Host: 127.0.0.1:8088`. Per SOP, host:port (+scheme) define an origin; this collapses all ports on a host into one. ¹Verified medium in JSON; placed here as a contained no-password-mode issue.
- **Impact:** In no-password (loopback-only) mode, any other local service on the Pi at a different port is a distinct real origin yet passes the guard and can issue state-changing writes (add nodes, restart service) to the root panel. With a password set, the Bearer token still blocks it → impact confined to no-password + sibling-local-service.
- **Fix:** Compare the full host:port authority (reconstruct Origin netloc with explicit-or-default port vs the raw Host authority); optionally reject on scheme mismatch.

### SEC-4 — Rebinding/CSRF guard provides no defense-in-depth in password mode; missing Origin always passes
- **File:** `pihy2/webui.py:144-172` · **Dimension:** security · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** With a password set, `_guard_write` only runs the Origin check `if origin:`; a request with no Origin/Referer passes unconditionally, and the IP/localhost Host restriction is skipped. So `_authed` is the *only* CSRF/rebinding defense in password mode. Today `/api/authinfo` (leaks whether a password is set) is reachable via rebinding.
- **Impact:** Low today (token gates sensitive endpoints), but a single future endpoint added before/without `_authed` becomes a full hole; currently only the `need_auth` boolean leaks cross-origin.
- **Fix:** Even in password mode, require no-Origin/Referer requests to pass a host==IP/localhost check, or require a custom header (e.g. `X-Requested-With`) browsers can't send cross-origin without preflight.

### SEC-5 — `clash_request` may re-send the API Bearer secret on an HTTP redirect
- **File:** `pihy2/manager.py:753-762` · **Dimension:** security · **Verified:** confirmed (2/0), reported medium → **low** · **Relation:** prior-missed
- **What's wrong:** `_clash_request` attaches `Authorization: Bearer <secret>` and calls `urlopen`, whose default opener follows 3xx and re-sends headers to the target. `_controller_base` validates only the *initial* loopback host, not the redirect target. *(Verifier downgrade: the secret is already handed to the hostile loopback listener on the first request, so a 302-issuer already has it — this is a redundant re-send, not a new leak path, hence defense-in-depth/hygiene.)*
- **Impact:** Low; subsumed by the precondition.
- **Fix:** Send via `_PinnedHTTPConnection` to the validated loopback IP with no redirect-following (treat 3xx as error), or build an opener stripping `Authorization` on cross-host redirects — for consistency with `fetch_text`/`_download_to_file`.

### SEC-6 — `resolve_download_url` / `current_ip` use unpinned, redirect-following `urlopen`
- **File:** `pihy2/manager.py:87-97, 720-734` · **Dimension:** security · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** The GitHub-API and `api.ipify.org` calls use the default opener (resolves the hostname itself, auto-follows redirects), unlike the hardened `fetch_text`/`_download_to_file`. The hosts are hardcoded trusted endpoints (and the resulting download URL is re-fetched via the pinned path), so it's an inconsistency, not directly attacker-controllable.
- **Impact:** Low; the GitHub-API call chooses the binary's download URL with full redirect-following and no pinning — a gap vs the project's own SSRF model.
- **Fix:** Route both through the same pinned-IP, no-redirect helper; at minimum disable redirect-following on the GitHub-API request.

### SEC-7 — `github_mirror` saved via WebUI is only https-prefix checked, not public-host validated
- **File:** `pihy2/webui.py:477-479` · **Dimension:** security · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `/api/settings` validates `github_mirror` only with `.startswith('https://')`; the public-host SSRF check lives only in `_apply_mirror()` at install time. So `https://127.0.0.1/` or `https://169.254.169.254/` can be persisted and is only rejected later when install runs. No request is issued at save time, and `_apply_mirror` blocks it at use time → defense-in-depth/consistency only.
- **Impact:** A bad/internal mirror is stored and fails far from where it was entered.
- **Fix:** Mirror the install-time `_resolve_public` validation in the handler; reject internal/loopback targets at save time.

### SEC-8 — `pihy2 config` CLI prints the clash secret and node passwords in cleartext
- **File:** `pihy2/__main__.py:60-61` · **Dimension:** security · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `cmd_config` does `print(Store().render_config())`, emitting `secret:` and all node `password:`/`uuid:` verbatim. The WebUI deliberately redacts the secret (`cfg.replace(sec, "******")`). The CLI doesn't — inconsistent secret posture (terminal scrollback, logs, screen-sharing, `pihy2 config | tee`).
- **Impact:** Low (runs as root, who owns `state.json` anyway), but undermines the WebUI's redaction invariant; an easy footgun.
- **Fix:** Centralize a `render_config(redact=True)` helper shared by CLI and WebUI; default `cmd_config` to redacted, or add `--with-secrets`. (Note: matching the WebUI means secret-only; mask node credentials too for a fully-redacted preview.)

### SEC-9 — Auth tokens / login-lockout use wall-clock `time()`; no-RTC Pi clock skew breaks sessions
- **File:** `pihy2/webui.py:26-32, 129-132, 319-323` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** Token expiry and lockout windows use `time.time()`. A Pi has no battery-backed RTC; pre-NTP the clock is the epoch/last-shutdown, then jumps forward at network-up. A token minted pre-sync gets an expiry far in the past after the jump (instant 401 / re-login loop); the lockout window across a jump can be bypassed or stuck. (The sub-update timer uses monotonic `OnUnitActiveSec` and is fine.)
- **Impact:** On the target platform (headless/no-RTC Pi), users can be locked into a re-login loop right after boot, or brute-force throttling defeated/over-applied around the NTP jump.
- **Fix:** Use `time.monotonic()` for the TTL/lockout deltas (store mint-time as monotonic, compare elapsed) — these are duration checks, immune to wall-clock steps.

### ROBUST-3 — `apply_config` takes only an in-process thread lock, not the cross-process `state_lock`
- **File:** `pihy2/manager.py:458-493` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `apply_config` serializes with the in-process `_APPLY_LOCK` only. The WebUI calls it after releasing `state_lock` (passing a freshly-loaded store), while the sub-update timer / `pihy2 sub ... --apply` run in separate processes via `_apply_outside_lock()` → `apply_config(Store())`. Two processes can render+write `config.yaml` concurrently; the fixed `MIHOMO_CONFIG + ".tmp"` path is stomped. `os.replace` keeps each write atomic (no half-file), but the on-disk config reflects whichever render landed last, built from a possibly-stale snapshot. *(Verifier: `pihy2 apply` itself DOES hold `state_lock` — `__main__.py:34`; the lockless CLI applier is the sub-update path, so the real race is WebUI-vs-timer.)*
- **Impact:** Under simultaneous timer + WebUI applies, a just-committed change can be silently dropped until the next apply; the shared `.tmp` name is a minor multi-writer hazard. No corruption.
- **Fix:** Hold `state_lock()` around render+write inside `apply_config` (and re-load the store under the lock), and/or write via `tempfile.mkstemp` in `MIHOMO_DIR` instead of a fixed `.tmp`.

### ROBUST-5 — `parser._int` raises `OverflowError` on inf/huge values (asymmetric to `config_gen._safe_int`)
- **File:** `pihy2/parser.py:38-43` · **Dimension:** robustness · **Verified:** confirmed (2/0), reported medium → **low** · **Relation:** prior-fix-incomplete
- **What's wrong:** `_int` does `int(float(v))` catching only `(TypeError, ValueError)`. For `'1e999'`/`inf`, `float(v)` returns infinity and `int(float('inf'))` raises `OverflowError` — not caught — violating the docstring's "never crashes" contract. Used for vmess `port`/`aid` and Clash-YAML `port`/`alterId`. `config_gen._safe_int` was hardened with `math.isfinite`; the parser wasn't. *(This dedups the separately-reported "inconsistent int-coercion helpers" style finding — same root issue and fix.)*
- **Impact:** Today every call site is wrapped in a broad `except Exception` (`parse_many:432`, `parse_clash_yaml:539`), so the only observable effect is a worse error message and a silently-dropped node — no crash. The "future caller outside the guards" impact is hypothetical.
- **Fix:** Mirror `_safe_int`: `try: f = float(v)` then `return int(f) if math.isfinite(f) else default`, and catch `OverflowError`. Better: have `parser` reuse `config_gen._safe_int` so there's one lenient-int implementation.

### ROBUST-6 — `_parse_vmess` raises `AttributeError` when base64 payload is valid JSON but not an object
- **File:** `pihy2/parser.py:221-230` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `j = json.loads(_b64decode(raw))` (guarded for decode errors) then immediately `host = j.get("add", "")`. If the decoded payload is a valid JSON array/string/number, `json.loads` succeeds and `j.get` raises `AttributeError`, bypassing the intended `ParseError`.
- **Impact:** A crafted `vmess://` produces `AttributeError` (caught generically by `parse_many`), so the user sees a confusing "解析异常" instead of the friendly message; type-confusion contract broken.
- **Fix:** After `json.loads`, `if not isinstance(j, dict): raise ParseError("VMess 链接不是合法的 base64(JSON)")`.

### ROBUST-7 — `_resolve_public` rejects a whole host if ANY resolved address is private (dual-stack hosts)
- **File:** `pihy2/manager.py:517-532` · **Dimension:** conflict · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `_resolve_public` iterates every `getaddrinfo` result and `_validate_ip` raises (rejecting the whole host) if any single address is private/reserved. Intended anti-rebinding, but a host with a public A and a ULA/reserved AAAA (split-horizon CDNs, placeholder AAAA) is refused entirely with "订阅地址不能指向内网…" despite a usable IPv4.
- **Impact:** Certain valid subscription/mirror URLs can't be fetched, with a misleading error; no in-tool override.
- **Fix:** Filter out private/reserved addresses and proceed if ≥1 public remains (still pinning to the validated public address(es)); reject only when zero survive.

### BUG-10 — `clash_delay` doesn't fully URL-encode the proxy name (default `quote` keeps `/`)
- **File:** `pihy2/manager.py:768-769, 778-779` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `urllib.parse.quote(name)` uses default `safe='/'`, so a name with `/` is injected raw into the path: `/proxies/HK%20/foo/delay` → `/foo` becomes an extra segment → wrong/404 endpoint. *(Verifier scope: `clash_select` is NOT affected — its caller passes the constant group "PROXY" and the node name travels in the JSON body, not the path. Bug is `clash_delay`-only.)*
- **Impact:** Delay testing shows 超时 for any node whose display name contains `/` (e.g. 'US 1/2', 'HK｜0.5x/Netflix' — common in subscriptions), with no explanation. Node switching is unaffected.
- **Fix:** Use `urllib.parse.quote(name, safe='')` in `clash_delay` (`manager.py:778`).

### BUG-11 — SS SIP002 plaintext userinfo can be silently mis-parsed (base64-decode-first with `errors='ignore'`)
- **File:** `pihy2/parser.py:288-297, 111-119` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** For SIP002, `_parse_ss` tries `_b64decode(userinfo).split(":",1)` first, falling back to plaintext only on error. But `_b64decode` decodes with `errors='ignore'`, so a plaintext `method:password` (used by 2022-blake3 ciphers) can decode to garbage; if that garbage contains a `:`, the split succeeds and the node silently gets a corrupted cipher/password instead of falling through.
- **Impact:** Rare but real: certain plaintext SIP002 userinfo yields a wrong cipher/password with no error → node fails to connect, credentials look plausible.
- **Fix:** Prefer plaintext when userinfo looks like `method:password` with a known cipher; only accept the base64 branch when the decoded text has exactly one structurally-valid `:` and the prefix is a plausible cipher. Or try plaintext first when userinfo isn't strict base64.

### BUG-12 — `node_to_link` double-brackets an already-bracketed IPv6 server
- **File:** `pihy2/parser.py:555` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** `hostb = f"[{host}]" if ":" in host else host`. Most paths store `server` unbracketed (via `_split_hostport`), but `proxy_to_node` stores `p.get('server')` verbatim. A Clash YAML `server` given as `[2001:db8::1]` keeps its brackets, so export produces `[[2001:db8::1]]:port`. *(Verifier scope: vmess is NOT affected — its export branch uses raw `host` for `add` and `_parse_vmess` reads `add` verbatim. Reachable only for Clash-imported vless/trojan/tuic/ss nodes whose `server` was supplied bracketed.)*
- **Impact:** Export of such a node yields a corrupt share link that can't be re-imported; round-trip fails for that node.
- **Fix:** Normalize on import: strip surrounding brackets in `proxy_to_node` (run host through `_split_hostport` or a strip helper) so `node_to_link`'s single bracketing convention holds.

### BUG-13 — `*.com`/`*.cn` auto-classify to a TLD-wide `DOMAIN-SUFFIX` (over-broad routing)
- **File:** `pihy2/config_gen.py:199-207` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `classify_rule('*.com')` → `('DOMAIN-SUFFIX','com')`, which matches every `.com` domain — a footgun, distinct from BUG-1 (this produces *valid* but semantically dangerous lines, no crash). The `*.example.com` case is intentional; the single-label/bare-TLD case is an unguarded edge.
- **Impact:** Silent over-broad routing/blocking from a plausible typo; no warning. (Requires the user to type a bare TLD wildcard.)
- **Fix:** When the residue after stripping `*.` has no dot, fall through to `DOMAIN-WILDCARD` (keep `*.com` literal) or reject — i.e. `if value.startswith("*.") and "." in value[2:]: return "DOMAIN-SUFFIX", value[2:]`.

### ROBUST-8 — `build_config` writes `log_level`/`tun_stack` enums without validation
- **File:** `pihy2/config_gen.py:441-443, 481-488` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `build_config` emits `s['log_level']`/`s['tun_stack']` verbatim; validation lives only in `webui.py:489-491`. An out-of-band edit/migration with `log_level='verbose'` or `tun_stack='wireguard'` flows straight into `config.yaml`; `_yaml_scalar` json-quotes it (no YAML injection) but `mihomo -t` rejects it, blocking apply.
- **Impact:** A bad persisted enum silently breaks every apply with a cryptic mihomo error rather than being clamped (unlike mixed_port/fake_ip_range/final, which self-protect).
- **Fix:** Clamp in `build_config`: `log_level` ∈ {silent,error,warning,info,debug} (fallback warning), `tun_stack` ∈ {system,gvisor,mixed} (fallback system).

### ROBUST-9 — `external_controller`/`secret` written to config without re-validating loopback
- **File:** `pihy2/config_gen.py:444-447` · **Dimension:** security · **Verified:** confirmed (2/0), reported medium → **low** · **Relation:** prior-missed
- **What's wrong:** The serializer emits `external-controller` + `secret` verbatim from settings; the loopback restriction is only at the API boundary and the clash client. `build_config([],[],{"external_controller":"0.0.0.0:9090","secret":"s"})` yields a non-loopback controller in the config. *(Verifier downgrade: the only user-facing write path already rejects non-loopback values, and no import path can populate one — reachable only via a manual root edit or a hypothetical validator regression. Defense-in-depth gap, not actively exploitable.)*
- **Impact:** If `external_controller` is ever non-loopback (direct edit / future regression), mihomo exposes its full control API on the LAN, guarded only by a short auto-generated secret now broadcast on that interface.
- **Fix:** In `build_config`, `urlparse` the host and fall back to `127.0.0.1:9090` when not in {127.0.0.1, ::1, localhost}, mirroring `_controller_base`.

### STORE-4 — `set_settings` blindly merges arbitrary keys; only the WebUI filters them
- **File:** `pihy2/store.py:260-261` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** `set_settings` is an unconditional `self.data["settings"].update(settings)`. The allowlist / `secret`-discard / loopback-`external_controller` protection lives entirely in `/api/settings`, not the store. Any other caller can overwrite `secret`, inject `external_controller`, or add unknown keys that flow into `build_config`. The protection is in the wrong layer.
- **Impact:** Low today (no current non-WebUI caller passes untrusted dicts), but a second caller would silently reintroduce the M-class settings injection.
- **Fix:** Move the allowlist + `secret`-discard + loopback check into `set_settings` so every caller inherits the invariant; the WebUI keeps its user-facing messages but relies on the store for the hard guarantee.

### DC-5 — `/api/nodes` form-add and `update_node` accept arbitrary dicts that bypass parser normalization
- **File:** `pihy2/webui.py:362-365, 448-454` · **Dimension:** data-contract · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `POST /api/nodes {"node":{...}}` → `add_node` directly, and `PUT /api/nodes/<id>` merges the raw body — neither runs `parser.proxy_to_node`'s normalization (stringify password/uuid/cipher/sni, `_int` alter_id, list-coerce `alpn`, drop unsupported networks, require uuid for vless/vmess/tuic). So `alpn` as a bare string → `build_config` emits `alpn: "h3,h2"` scalar (mihomo rejects), `network:"quic"` → silently tcp (dead node), missing-uuid vless persists. The frontend never exercises the `node` branch, so this path is unguarded. *(Verifier: the malformed-alpn-scalar case is caught by `mihomo -t` and rolled back; the strongest real impact is the silently-coerced unsupported network producing a dead node `-t` does NOT reject, plus string-typed port/alter_id and missing-uuid nodes persisting.)*
- **Impact:** State populated with node dicts whose shapes violate config_gen's contract → invalid config.yaml or silently-broken nodes; the import-path validation is absent for direct-dict ingestion.
- **Fix:** Factor `proxy_to_node`'s coercion block into a reusable `normalize_node(dict)` and call it from `add_node`/`update_node` so all four producers (share-link, YAML, form-add, edit-PUT) converge.

### DC-6 — `github_mirror` lives outside `DEFAULT_SETTINGS`; allowlist is special-cased
- **File:** `pihy2/webui.py:461-479` · **Dimension:** data-contract · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `github_mirror` is security-sensitive (changes where the root binary downloads from) but isn't in `config_gen.DEFAULT_SETTINGS`; the allowlist compensates with `set(DEFAULT_SETTINGS) | {"github_mirror"}`. It has no documented default, isn't seeded by `_new_state`/`_migrate`, and any future code iterating `DEFAULT_SETTINGS` silently omits it. Not exploitable (https check enforced), but the contract is fragile.
- **Impact:** A refactor trusting `DEFAULT_SETTINGS` as the canonical key set would drop validation/persistence of the mirror URL.
- **Fix:** Add `"github_mirror": ""` to `DEFAULT_SETTINGS` so the allowlist becomes `set(DEFAULT_SETTINGS); allowed.discard("secret")` and the key is seeded consistently.

### DC-7 — `_migrate` doesn't de-duplicate pre-existing duplicate node ids
- **File:** `pihy2/store.py:142-153` · **Dimension:** data-contract · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** `_migrate` backfills `_seq` and assigns ids only to falsy-id nodes; it doesn't detect two nodes already carrying the same non-empty id (possible in hand-edited/third-party state; `_id_num` is also 0 for non-numeric ids). `update_node` updates only the first match; `delete_node` deletes ALL matches; `reorder` uses the shared index. M6 fixed missing `_seq` but not pre-existing duplicate ids.
- **Impact:** Imported state with colliding ids → update hits the wrong node, delete removes multiple at once. Edge case, silent corruption when it occurs.
- **Fix:** In `_migrate`, detect duplicate ids and reassign fresh ids via `_next_id_on`, like the falsy-id path.

### ROBUST-10 — Duplicate subscriptions (same URL) accepted, producing duplicate nodes
- **File:** `pihy2/webui.py:397-415` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `add_subscription` does no URL dedup. Submitting the same URL twice creates two sub records, each tagged onto its own copy of the same parsed nodes; `_dedup_names` then renames the duplicates (NodeX, NodeX-2…), doubling the proxy list and confusing delay/selection.
- **Impact:** Accidental re-add silently doubles all nodes; the user must delete one sub.
- **Fix:** Reject or merge when an existing sub has the same normalized URL (return the existing sub).

### FRONT-3 — `web-pw-clear` checkbox not reset by `renderSettings`; sticky "clear password" intent
- **File:** `web/app.js:467-469, 491-498` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** new
- **What's wrong:** `renderSettings()` resets `web-pw` value but never `web-pw-clear`. `saveWebui` only clears the checkbox on a *successful* save. If a save fails (e.g. server rejects clearing the password while bind is 0.0.0.0), the checkbox stays checked; a later unrelated save (e.g. port-only change) re-sends `password:''`.
- **Impact:** A failed password-clear leaves a sticky checkbox; a later save can unintentionally remove the WebUI password (security downgrade to no-auth) on a loopback bind.
- **Fix:** Reset `el('web-pw-clear').checked=false` inside `renderSettings` (alongside the `web-pw` value reset), not only on save success.

### FRONT-4 — `loadState()` throws unhandled (UnhandledPromiseRejection) on 401 at several call sites
- **File:** `web/app.js:10-20, 53, 489, 497` (+ commitNodes/deleteNode/saveNode) · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** new
- **What's wrong:** `api()` rethrows `new Error('未登录')` on 401 after `showLogin()`. `boot()` wraps `loadState` in try/catch, but `doLogin`/`saveSettings`/`saveWebui`/node mutations `await loadState()` without one. If the token expires between the write and the refresh, the await rejects uncaught. *(Verifier: `loadState` already returns false on `!s.ok` — the gap is specifically the 401 *throw* path; the doLogin path is practically unreachable since the token was just minted.)*
- **Impact:** Uncaught rejections; post-await UI cleanup (success toasts at 97/103/110) is skipped on the 401 edge. Mostly cosmetic.
- **Fix:** Make `api()` not throw on 401 (return `{ok:false,_unauth:true}` after `showLogin()`) so `loadState`'s existing `if(!s.ok) return false` handles it; or `const s = await api('GET','/api/state').catch(()=>({}))`.

### SEC-10 / SYSCTL — Uninstall removes the sysctl drop-in but never reverts runtime `ip_forward`/`rp_filter`
- **File:** `pihy2/manager.py:413-443, 803-823` · **Dimension:** security/robustness · **Verified:** confirmed (2/0), reported medium → **low** · **Relation:** prior-missed / prior-fix-incomplete
- **What's wrong:** `uninstall()` calls `set_ip_forward(False)`, which for `on=False` only `os.remove`s `/etc/sysctl.d/99-pihy2.conf` and (by design, to avoid clobbering Docker) never runs `sysctl -w ...=0`. So after uninstall, the running kernel keeps `ip_forward=1` and `rp_filter=2` (loose, a system-wide anti-spoofing weakening pihy2 introduced) until reboot, with no pihy2 artifact explaining it. *(Three separate findings — the security-framed, robustness-framed, and conflict-framed versions of the same residue — are merged here.)*
- **Impact:** Post-uninstall the host keeps forwarding + loose rp_filter until reboot; mild anti-spoofing relaxation, self-heals on reboot, no remote vector → low.
- **Fix:** On uninstall specifically (distinct from per-apply), best-effort restore the values pihy2 changed: snapshot the pre-pihy2 `rp_filter` into `state.json` at first set and restore it, guarding any `ip_forward=0` with a check that no other forwarding consumer exists; at minimum log a clear warning recommending a reboot. (Leave the per-apply no-clobber design intact; `ip_forward` is best left alone — commonly already 1 and shared.)

### CONFLICT-6 — Normal uninstall leaves `/etc/modules-load.d/tun.conf` behind; messaging implies full cleanup
- **File:** `pihy2/manager.py:285-294, 812-823` · **Dimension:** robustness/conflict · **Verified:** confirmed (2/0) · **Relation:** new / prior-missed
- **What's wrong:** `ensure_tun()` writes `/etc/modules-load.d/tun.conf` to auto-load the tun module at boot; `uninstall` only removes it in the `--purge` branch. A plain `pihy2 uninstall` leaves it, so the host keeps loading tun every boot. Separately, `--purge` removes that exact path unconditionally — if the host had its *own* `tun.conf` (for an unrelated VPN), purge deletes a directive the host relied on.
- **Impact:** Residual boot-time module config after a normal uninstall (low — tun is harmless); and a purge can break an unrelated VPN's boot-time tun load.
- **Fix:** Use a pihy2-specific filename (`/etc/modules-load.d/pihy2-tun.conf`) so pihy2 only ever removes its own file; or remove `tun.conf` in the base uninstall path and note it in the message.

### INSTALL-2 — `install.sh` `cp -r docs` is non-idempotent on re-run (stale docs accumulate)
- **File:** `install.sh:37-41` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** new
- **What's wrong:** The line-37 `rm` only clears `pihy2/`/`web/`. The copy loop also copies `docs`; `cp -r "$SRC_DIR/docs" "$INSTALL_DIR/"` *merges* into an existing `docs` dir, so stale files from a prior version are never cleaned. *(Verifier scope: README.md is a regular file `cp -r` overwrites cleanly — the defect is `docs/` only.)*
- **Impact:** Stale docs persist across upgrades; users may read outdated docs.
- **Fix:** Add `docs` to the pre-copy `rm -rf` list (guarded by the `SRC_DIR != INSTALL_DIR` check from INSTALL-1), or `rsync --delete` the tree.

### INSTALL-3 — `install.sh` checks Python presence but not version
- **File:** `install.sh:24-29` · **Dimension:** compatibility · **Verified:** confirmed (2/0) · **Relation:** new
- **What's wrong:** Checks `command -v python3` and prints the version but never asserts a minimum. The code uses `from __future__ import annotations` (every module) and pervasive f-strings (hard floor 3.7) plus `ThreadingHTTPServer`/`subprocess.run(capture_output=...)` (also 3.7). On an old distro the wizard dies with an opaque SyntaxError/ImportError. *(Verifier: true floor is 3.7, not 3.8.)*
- **Impact:** On old hosts the install proceeds then crashes the wizard with a confusing traceback instead of a clear version message. Low likelihood on modern RPi OS.
- **Fix:** After the presence check: `python3 -c 'import sys; sys.exit(0 if sys.version_info>=(3,7) else 1)' || { red "需要 Python 3.7+"; exit 1; }`.

### COMPAT-2 — `detect_arch()` default-falls-back to arm64 for `armv8l`/`i686`
- **File:** `pihy2/manager.py:75-77` · **Dimension:** compatibility · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** After the arm64/amd64/armv7/armv6 branches, any other `machine` → `return "arm64"`. Two real values fall through: `armv8l` (32-bit RPi OS userland on a 64-bit kernel, Pi 4/400/CM4) and `i686`/`i386` (32-bit x86). Both get the arm64 asset. *(Verifier: install does NOT silently complete — `[tmp_bin,"-v"]` fails with Exec-format error and raises RuntimeError "下载的二进制无法运行…（…架构不符）" — but the message gives no hint that auto-detection picked the wrong asset.)*
- **Impact:** `armv8l`/`i686` get an incompatible binary → install aborts with a partially-informative error that doesn't reveal the misdetection. Affects 32-bit-on-64-bit-kernel Pi and x86-32 hosts the CLI otherwise advertises.
- **Fix:** Map `armv8l`/bare `arm`/`armhf` → `armv7` (32-bit userland even under a 64-bit kernel); map `i686`/`i386`/`i586`/`x86` → the `386` asset (mihomo ships `linux-386`; add a `386` `PINNED_SHA256` or the mirror path rejects it at line 218); for a genuinely unknown machine, **raise** `unsupported arch: <m>` showing the actual machine string instead of guessing arm64.

### COMPAT-3 — Overlay relies on `inset: 0` shorthand with no longhand fallback (iOS Safari < 14.1)
- **File:** `web/style.css:253` · **Dimension:** compatibility · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `.overlay { position: fixed; inset: 0; }` is the sole positioning for login/modals/confirm dialogs. `inset` shipped in Safari/iOS 14.1 (Oct 2020); with no `top/right/bottom/left` fallback, older mobile browsers ignore it and the fixed overlay falls back to `auto` offsets → shrinks to content, not full-screen.
- **Impact:** On iOS < 14.1 the overlay is mis-positioned (no backdrop coverage, off-center card). *(Verifier: NOT a functional lockout — `display:flex` still lays out the card and its inputs remain interactive; the degradation is cosmetic, and the field exposure in 2026 is tiny — iPhone 6-era only, on a technical-user admin panel.)*
- **Fix:** Add explicit longhand before the shorthand: `position: fixed; top:0; right:0; bottom:0; left:0; inset:0;`.

### CLI-2 — Subscription auto-update timer never installed when the first sub is added outside the wizard
- **File:** `pihy2/webui.py:397-415, 509-513, 545-548` · **Dimension:** feature-completeness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `install_sub_timer()` is only called from the wizard and from `/api/settings` *when `os.path.exists(SUB_TIMER)` is already true*. The sub-add paths (`/api/subs`, CLI `sub add`) never call it. On a system where the timer wasn't created at wizard time, adding a sub later doesn't establish auto-updating, and adjusting the interval before the timer exists silently no-ops.
- **Impact:** Mostly benign (the wizard always installs the timer even with zero subs), but a sub added on a host installed without the wizard (manual setup, or after `uninstall` removed the timer but left state) never auto-updates, contradicting the stated promise, no error surfaced.
- **Fix:** Call `manager.install_sub_timer(...)` (idempotent) after a sub is first registered in `/api/subs` and CLI `sub add`; or remove the `os.path.exists(SUB_TIMER)` gate so saving the interval always (re)installs.

### FEAT-2 / STYLE — `process-name` rule type is classifiable by both maps but absent from the WebUI dropdown
- **File:** `web/app.js:338-339, 366` (+ `config_gen.py:178`) · **Dimension:** feature-completeness/data-contract · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** Both `classify_rule` (backend) and `classifyRule`'s `map` (frontend) include `'process-name': 'PROCESS-NAME'`, but `RULE_TYPES` (which drives the rule `<select>`) omits it. So PROCESS-NAME can't be chosen from the UI, and the supported-type set is duplicated in three places (dropdown, JS map, Python map) that have drifted. An imported `process-name` rule renders correctly server-side but its `<select>` defaults to the first option while STATE keeps `process-name`. *(Two separately-reported findings merged. Verifier: the onchange fires only on explicit interaction, so there's no silent corruption merely from opening the tab.)*
- **Impact:** Minor capability gap + 3-way data-contract drift; per-process routing is half-supported (backend yes, UI no).
- **Fix:** Add `['process-name','进程名']` to `RULE_TYPES`; better, derive the type list from a single backend source (like `preset_catalog`) so the three definitions stop drifting.

### DC-8 — Frontend `isIPv6`/`isIPv4` diverge from Python `ipaddress`; rule preview lies for malformed IPs
- **File:** `web/app.js:344-360, 369-377` · **Dimension:** data-contract · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** CODE_REVIEW (line 115) claims the frontend IP validators were aligned with Python `ipaddress`. They aren't: `isIPv6` only checks the hextet charset and group *count*, never that each hextet is ≤4 hex digits, and accepts `12345::1` / `1.2.3.4.5::1` which Python rejects. For an `ip-cidr` rule, `classifyRule` then shows a confident `IP-CIDR,12345::1/128,PROXY` preview, but `classify_rule` raises `ValueError` and `build_config` silently drops the whole rule.
- **Impact:** The "generated rule" preview (described as "preview = final result") is wrong for malformed IPv6; the user believes a routing rule is active when it was silently discarded, so traffic takes a different path. *(Verifier: the rule is dropped, not mis-routed to a wrong explicit policy — no confidentiality leak; misleading-preview + inactive-rule, hence medium-low.)*
- **Fix:** Validate each non-empty hextet against `/^[0-9a-fA-F]{1,4}$/` and restrict the embedded-IPv4 (dot) form to the trailing group only; or route the preview value through a single backend `/api/classify` endpoint so JS and Python can't diverge.

### STYLE-1 — Auto-heuristic `*`/`?` → DOMAIN-WILDCARD duplicated verbatim in Python and JS
- **File:** `pihy2/config_gen.py:202-203` (+ `web/app.js:379`) · **Dimension:** robustness/style · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `classify_rule` maps any value containing `*` OR `?` to `DOMAIN-WILDCARD`, duplicated exactly in the frontend. A dotless value like `a?b` becomes a wildcard domain rather than a keyword. *(Verifier reframe: DOMAIN-WILDCARD is a valid mihomo type and `?`/`*` are legit tokens — the value is most likely ACCEPTED, not rejected; the real defect is the surprising classification plus the verbatim Python/JS duplication that's only coincidentally in sync.)*
- **Impact:** Surprising auto-classification of `?`/`*`-bearing values; the parallel heuristic is a standing maintenance hazard.
- **Fix:** Make the server the single source — return the generated rule line/classification from the API and have the UI render it rather than reimplementing `classifyRule` in JS; at minimum cross-link the two copies with a comment.

### STYLE-2 — `_SAFE_DIRECT_CIDRS` (config_gen) and the manager SSRF private-net set are independent literal lists that have diverged
- **File:** `pihy2/config_gen.py:40-43` (+ `manager.py:502, 511-513`) · **Dimension:** conflict/style · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** "Private/internal" networks are hand-written in two places. `_SAFE_DIRECT_CIDRS` omits IPv6 ULA/link-local (fc00::/7, fe80::/10) and 0.0.0.0/8; the manager guard covers them via `is_*` flags. They serve different purposes (keep-LAN-alive routing vs SSRF) but are maintained separately (the CGNAT entry was added to both only after M9). *(Verifier: the "must stay in sync with the SSRF guard" claim is weaker than stated — the lists legitimately differ; the strongest concrete defect is the IPv6 safe-direct gap, gated behind non-default `ipv6:true`.)*
- **Impact:** When `ipv6` is enabled, an fd00::/8 LAN route is NOT in the safe-direct prepend list, so LAN IPv6 traffic could be proxied; future private-net policy changes risk SSH-cutting or SSRF gaps.
- **Fix:** When `s["ipv6"]` is true, also prepend `IP-CIDR6,fc00::/7,DIRECT,no-resolve` and `IP-CIDR6,fe80::/10,DIRECT,no-resolve`. Ideally define the private-net set once and derive both uses from it.

### STYLE-3 — `current_ip` default `retries=1` performs no retry (contradicts its docstring)
- **File:** `pihy2/manager.py:720-734` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** new
- **What's wrong:** The docstring promises retries on cold start, but `retries=1` makes `range(max(1,retries))` iterate once and the backoff branch never runs. Every caller (`/api/status`) gets a single attempt.
- **Impact:** Right after a mihomo restart, the first IP probe through the not-yet-warm proxy often times out → status shows "(获取失败…)" even though a retry 2s later would succeed.
- **Fix:** Default `retries=3` in the signature (or have `/api/status` pass `retries=3`); the backoff logic is correct once `retries>1`.

### ROBUST-11 — `/api/status` unconditionally probes egress IP (up to 8s blocking) even when mihomo is down
- **File:** `pihy2/webui.py:245-252` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** `/api/status` always calls `current_ip()` (urllib to `api.ipify.org`, `timeout=8`), regardless of whether mihomo is installed/running. When the proxy is down (the common "let me check status" case) this blocks the status response for the full 8s. *(Verifier: there's no background polling of `/api/status` — `refreshStatus()` fires on load/login/after actions; with default retries=1 it's a single 8s attempt.)*
- **Impact:** The primary troubleshooting view stalls ~8s on each open/reload/action during an outage — feels dead exactly when diagnosing.
- **Fix:** Skip `current_ip()` when `not os.path.exists(MIHOMO_BIN)` or mihomo isn't active; or move egress-IP probing to a lazy on-demand endpoint; and/or lower the status-path timeout.

### TEST-4 — `set_subscription_nodes` active-node preservation untested
- **File:** `tests/test_basic.py:334-348` · **Dimension:** test-gap · **Verified:** confirmed (2/0), reported medium → **low** · **Relation:** prior-missed
- **What's wrong:** `set_subscription_nodes` has non-trivial active-node-restore logic (key on (name,server,port), then same-name, then first node, then dangling fallback) flagged as a "rejected false positive" in CODE_REVIEW but never pinned with a test. `reorder_nodes` and `delete_subscription`'s active-fallback are also untested. *(Verifier: the code is correct — this is a regression-prevention gap, hence low.)*
- **Impact:** The active-node-restore logic (which proxy a user's traffic flows through after a timer-driven update) can regress with no test failing.
- **Fix:** Store test: set active, call `set_subscription_nodes(sid, new_nodes)` with a (name,server,port)-matching node, assert `active_node()` still points to it; assert same-name and first-node fallbacks; assert deleting an active sub re-points active to a survivor.

### TEST-5 — `to_yaml` serializer quoting/edge-case coverage is shallow
- **File:** `tests/test_basic.py:309` · **Dimension:** test-gap · **Verified:** confirmed (2/0), reported medium → **low** · **Relation:** prior-missed
- **What's wrong:** Only one direct serializer assertion (dangerous *key* quoting). No direct test for value-side hazards (`:`, leading/trailing space, `#`, `@`, leading `!`/`&`/`*`/`-`, multi-line, empty, "true"/"yes"/"no", leading-zero passwords). Most YAML output is validated only transitively, and the `mihomo -t` full-parse path is skipped without `MIHOMO` set. *(Verifier: the serializer always quotes scalars via `json.dumps`, so the listed failures can't currently occur — this is regression-locking, not an active bug.)*
- **Impact:** A future serializer regression (unquoted `:` in a value, dropped leading-zero quotes) would pass `168/0`.
- **Fix:** Round-trip generated YAML through the in-repo `yaml_lite.load` for a battery of hostile values (and exercise `_inline_nested` list-in-dict slicing) — zero external dependency.

### TEST-6 — `mihomo -t` validation (the only test that parses generated YAML) skipped by default
- **File:** `tests/test_basic.py:602-635` · **Dimension:** test-gap · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** Full-config YAML validation runs only if `MIHOMO` points at a real binary; otherwise it prints "跳过 mihomo -t". In a default/CI run no rendered config is parsed by any YAML engine — all config assertions are substring checks. The repo ships `yaml_lite.load` and could validate parseability with zero deps. *(Verifier: `yaml_lite` is the project's own subset parser, so a round-trip catches gross structural breakage, not mihomo-specific schema errors — weaker but still worthwhile.)*
- **Impact:** The suite reports green while never confirming `render(...)` output is parseable YAML on machines without mihomo (the common dev/CI case).
- **Fix:** For each rendered config, additionally `yaml_lite.load(text)` and assert a dict with expected top-level keys; keep `mihomo -t` as the stronger optional check.

### TEST-7 — Several config-gen assertions are weak substring checks
- **File:** `tests/test_basic.py:209-214` · **Dimension:** test-gap · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** Many assertions test only that a substring appears anywhere in the serialized text (`'"PROXY"' in text`, `'allow-lan: false' in g_off`), not that the value is in the correct structural position. Combined with TEST-6 (no re-parse), structurally-broken-but-substring-present output passes.
- **Impact:** These tests give weaker guarantees than they appear to.
- **Fix:** Assert against the parsed structure — `build_config(...)` already returns a dict; check `cfg['proxy-groups']` names, `cfg['allow-lan']` rather than substring membership.

### TEST-8 — `node_to_link` export coverage omits trojan/tuic/reality field fidelity
- **File:** `tests/test_basic.py:124-146` · **Dimension:** test-gap · **Verified:** confirmed (2/0) · **Relation:** prior-missed
- **What's wrong:** The multi-protocol round-trip loop only asserts `password or uuid` and `server` survive — not trojan `sni`, tuic `uuid`+`password`+`alpn`, or vless `reality_pbk`/`sid`/`flow`. (This is exactly the class of export bug that BUG-5/BUG-6 fall into.)
- **Impact:** An export bug dropping tuic's password or trojan's sni survives the suite.
- **Fix:** Extend the loop to compare a protocol-specific field set per type (trojan: sni; tuic: uuid AND password AND alpn; vless reality: reality_pbk/sid).

### TEST-9 — `wizard.py` and the `app.js` XSS fix have no automated coverage
- **File:** `tests/test_basic.py:414-425` · **Dimension:** test-gap · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- **What's wrong:** CLI coverage exists for `build_parser`, but `wizard.py` (interactive installer, incl. the getpass-fallback concern) is entirely untested, and `app.js` — home of the H2 stored-XSS fix (sub name in inline onclick) — has no test of any kind. The XSS fix is documented, not verified.
- **Impact:** The fixed XSS escaping and any pure wizard logic can regress with no signal. (Lower severity since app.js is hard to unit-test in a stdlib-only Python repo.)
- **Fix:** Extract pure helpers from `wizard.py` and unit-test them; for app.js, at minimum add a server-side test asserting sub names are stored verbatim and never reflected into an HTML/JS context server-side (document that escaping is client-side).

### STYLE-4 — Inconsistent error contracts across `clash_*` helpers
- **File:** `pihy2/manager.py:765-799` · **Dimension:** style · **Verified:** confirmed (1/0) · **Relation:** prior-missed
- **What's wrong:** Four sibling clash helpers use three return conventions for the same failure: `clash_select` → `(bool, str)`, `clash_delay` → `None`, `clash_connections` → `None`, `clash_close_all` → `bool`. All use broad `except Exception`, hiding timeout vs auth vs JSON.
- **Impact:** Maintainability/debuggability: a failing call is reported as `False`/`None`/error-string depending on the helper, and bare excepts mean the operator never sees the cause.
- **Fix:** Standardize on one contract (e.g. `(ok, data_or_msg)`), narrow the excepts to `(URLError, OSError, JSONDecodeError, socket.timeout)`, and log the cause at debug.

---

## Info

### INFO-1 — Wizard writes settings straight to `store.data`, bypassing `/api/settings` validation
- **File:** `pihy2/wizard.py:139-162` · **Dimension:** robustness/style · **Verified:** confirmed (2/0), reported low → **info** · **Relation:** prior-missed
- The wizard assigns settings directly into `store.data['settings']` with no shared validation. Currently safe (values are already correct types), but it means the "all settings writes go through validation" invariant isn't centralized — a future wizard prompt producing a bad value would be validated via the API but not via the wizard. **Fix:** route wizard settings through a shared `sanitize_settings`/`set_settings` helper used by both. (No observable defect today → info.)

### INFO-2 — `refresh_all_subscriptions` is dead code with an inconsistent shape
- **File:** `pihy2/manager.py:655-657` · **Dimension:** bug · **Verified:** confirmed (1/0) · **Relation:** new
- Returns `{id: count}` discarding the error list and has no caller anywhere (webui/`__main__` implement their own loops). A future caller would silently lose per-sub error reporting. **Fix:** remove it, or return per-sub `(count, errors)` matching `refresh_subscription` and wire it into the update paths.

### INFO-3 — TUIC export always emits `congestion_control`/`udp_relay_mode` defaults
- **File:** `pihy2/parser.py:356-357, 599-602` · **Dimension:** style · **Verified:** confirmed (1/0) · **Relation:** new
- The TUIC parser always populates `congestion` (bbr) / `udp_relay_mode` (native) even when absent from the link, and `node_to_link` re-emits them, so exported links are noisier than the input. Harmless round-trip. **Fix:** only store these when present in the source; let config-gen apply defaults (it already does via `node.get(...) or 'bbr'`).

### INFO-4 — Duplicated/asymmetric `alpn` handling across parser and config_gen
- **File:** `pihy2/parser.py:107-108` (+ builders) · **Dimension:** style · **Verified:** confirmed (1/0) · **Relation:** prior-missed
- ALPN normalization is spread across `_alpn`, `proxy_to_node`, several builders (`or ['h3']` vs `if node.get('alpn')`), and `node_to_link` (hysteria2 special-cases `['h3']`). If a *string* alpn reaches a builder (externally-edited state), it's emitted as a scalar `alpn: "h3,h2"` instead of a list, which mihomo rejects. **Fix:** normalize alpn to a list once (in `_migrate` or a single helper) and have builders rely on that invariant.

### INFO-5 — Block-scalar (`|`/`>`) content is comment-stripped and indentation-flattened
- **File:** `pihy2/yaml_lite.py:176-191, 232-238` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- Every line is `_strip_comment`-ed and indent-normalized at `_Reader` construction *before* block-scalar context is known, so a `|` literal value has any ` #` tail truncated and internal indentation flattened. *(Verifier correction: `load('k: |\n  line1 # not a comment\n    indented')` returns `{'k':'line1\nindented'}` — the second line is kept but flattened, not dropped.)* Low/info because the affected fields (certs/headers) aren't in `proxy_to_node`'s supported set. **Fix:** preserve raw lines for block-scalar regions (skip comment-strip/indent-normalize, or re-scan raw source for the block range).

### INFO-6 — Folded `>` collected identically to literal `|`; chomping indicators ignored
- **File:** `pihy2/yaml_lite.py:232-238, 280-282, 330-332` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- Both `|` and `>` join with `\n`, so `>` folding (newline→space) isn't applied and `|-`/`|+`/`>-` chomping is ignored (a `|` block drops its trailing newline). Low for typical Clash subs (PEM uses `|`, tolerates missing trailing newline; `>` is rare). **Fix:** pass the indicator into `_block_scalar` — fold non-empty lines with a space for `>`, honor chomping.

### INFO-7 — Block scalars drop internal blank lines (reader pre-filters empties)
- **File:** `pihy2/yaml_lite.py:188-191, 232-238` · **Dimension:** bug · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- `_Reader.__init__` skips every blank line globally before block-scalar context is known, so internal empty lines in a `|`/`>` block are removed and surrounding lines concatenated. Low for PEM (no internal blanks). Also means error-message line numbers don't reflect the source. **Fix:** preserve blank lines during tokenization (sentinel/raw), or scan raw source for block-scalar ranges.

### INFO-8 — Aliases (`*name`) inside flow collections not resolved (block-context works)
- **File:** `pihy2/yaml_lite.py:120-135` · **Dimension:** robustness · **Verified:** confirmed (2/0) · **Relation:** prior-fix-incomplete
- `_scalar` has no alias handling, so `[*alpn, h3]` yields the literal `'*alpn'`. Block-level aliases (the common case) work. *(This is the same root cause as BUG-2, surfaced for non-merge flow collections — listed separately because BUG-2's blast radius (dropped merged keys) is materially worse than a literal-sigil field value.)* **Fix:** thread the reader's anchor dict into `_scalar`/flow parsing and resolve `*name`; the same fix resolves BUG-2.

---

## Uncertain (recorded, not asserted)

- **BUG-13b / latest-binary integrity (`manager.py:224-253`)** — reported low, **1 confirm / 1 refute**. One verifier holds that the non-checksummed GitHub-direct (online-latest) and armv7-fallback paths are the *documented, accepted* resolution of CODE_REVIEW M10/M12 (operator chose "force GitHub direct + reject mirror + warn", gated by TLS + host-IP pinning + redirect re-validation + an explicit warning), so no code change is required and it duplicates SEC-2. The actionable residue (fetch+verify upstream `checksums.txt`) is folded into **SEC-2**.
- **DC-9 / subscription `count` vs config_gen's effective node set (`store.py:228-254`)** — reported low, **1 confirm / 1 refute**. `sub["count"] = len(added)` can exceed the proxies actually present if `build_config` later drops nodes. One verifier corrected the mechanism (no "unsupported builder" drop — `node_to_proxy` falls back to hysteria2; real drops are missing-`server` and builder-exception) and another argued it's effectively *unreachable* for subscription-sourced nodes because `proxy_to_node` already raises `ParseError` for unsupported types / missing servers before storage — making it an info-level theoretical note. If pursued: compute `count` from nodes surviving `build_config`, or surface per-node `errs` in the sub record.
- **CLI-3 / `pihy2 add --apply` and `sub … --apply` ignore apply failure in exit code (`__main__.py:79-81, 103-104, …`)** — reported medium, **0 confirm / 0 refute** (no verifier reached it). The claim: `cmd_add`'s `--apply` and `_apply_outside_lock()` print the message but discard the `ok` boolean, so the process exits 0 even when `apply_config` returned False, defeating exit-code-based error handling in the systemd timer (`sub update all --apply`) and any CI/cron. If confirmed, capture `ok` and `sys.exit(1)` on failure, mirroring `cmd_apply` (line 38). Flagged for a targeted follow-up since it was unverified.