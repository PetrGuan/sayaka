# AI Footprint v1 (macOS, read-only)

The user chooses one tool's data directory through the App's security-scoped
folder picker. Sayaka scans that explicit root without reading file contents or
following links. `sayaka_scan_ai_footprint_v1` projects only exact top-level
names from the immutable scan tree. A documented signature must be present before
any child is attributed to the selected tool. A custom directory is supported
only when the user chooses its actual root and the marker matches; this feature
does not infer ownership from `.claude`, `.codex`, `.copilot`, `output`, file
extensions, or a path elsewhere on disk. Recognition requires `projects` plus
one of Claude's history/checkpoint/memory/credential entries; Codex `sessions`
plus configuration/history/archive evidence; Copilot `session-state` plus
configuration/log/index evidence; or ComfyUI's `folder_paths.py` and `main.py`.
Generic `settings.json`, `config.toml`, and `logs` names alone never establish
ownership. A newer or sparse installation may stay unrecognized until these
independent entries appear; that is safer than attributing an unrelated folder.

The projection reports known logical bytes, unknown file counts, partial
coverage, and cloud placeholders separately. No timestamp or reliable active
process identity exists in the scan snapshot, so last activity and running
state are explicitly unknown. The user must treat an active or shared folder as
in use. There is no cleanup action or execution identifier; paths are display
evidence and Reveal in Finder targets only.

| Tool, evidence | Exact top-level names | Meaning and loss if removed |
| --- | --- | --- |
| [Claude Code directory](https://code.claude.com/docs/en/claude-directory) | `projects`, `history.jsonl`, `file-history`, `agent-memory` | Sessions, history, checkpoints and memory. Keep; removing them loses resume or recall. |
| Claude Code | `debug`, `cache` | Logs/cache. May be recreated, but an active session may still use them. Preview only. |
| Claude Code | `settings.json`, `.credentials.json` | Settings and credentials. Never a cleanup candidate. Claude offers retention settings and `claude project purge --dry-run` for project-scoped state; this App never invokes it. |
| [Codex configuration source](https://github.com/openai/codex/blob/main/codex-rs/core/src/config/mod.rs) | `sessions`, `archived_sessions`, `history.jsonl`, `memories`, `log` | Sessions/history/memory are user state; logs are diagnostics. Layout must be rechecked for supported versions before any cleanup rule. |
| Codex | `config.toml`, `auth.json` | Settings and authentication. Never a cleanup candidate. `CODEX_HOME` can relocate the actual root. |
| [Copilot CLI directory](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference) | `logs`, `session-state`, `command-history-state`, `session-store.db`, `plugin-data` | Logs differ from session restore, command history, cross-session index and plugin state. Only logs are documented as safely deletable; this version still previews only. `COPILOT_HOME` can relocate the root and its cache lives elsewhere. |
| Copilot CLI | `settings.json`, `config.json`, `mcp-secrets` | Settings, authentication and secrets. Never a cleanup candidate. |
| [ComfyUI path source](https://github.com/Comfy-Org/ComfyUI/blob/master/folder_paths.py) | `folder_paths.py`, `output`, `input`, `models`, `user`, `temp` | `folder_paths.py` marks a source tree. Output/input are media assets, models are weights, `user` holds workflows/settings, and `temp` may be in use. All are preview-only. CLI options and setters can redirect these directories; users must select their actual root and this version does not claim redirected paths. |

Rules are version 1 and intentionally incomplete. Unknown children contribute
to the root's total but receive no tool-specific classification. Never treat a
reported zero as an empty folder when scan coverage or byte measurement is
unknown. A future Trash capability requires separate per-rule evidence and a
new identity-bound, revalidated execution contract; this report grants none.
