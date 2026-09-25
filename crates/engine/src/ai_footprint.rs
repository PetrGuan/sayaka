// SPDX-License-Identifier: MPL-2.0

//! Read-only projection of a user-authorized scan tree. No file content is read,
//! no classification grants execution rights, and paths are display evidence only.

use crate::model::ResourceKind;
use crate::scan::index::ScanTree;
use serde::Serialize;
use std::ffi::OsStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Claude,
    Codex,
    Copilot,
    ComfyUI,
}

impl Tool {
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::Claude),
            2 => Some(Self::Codex),
            3 => Some(Self::Copilot),
            4 => Some(Self::ComfyUI),
            _ => None,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Claude => "claude_code",
            Self::Codex => "codex",
            Self::Copilot => "copilot_cli",
            Self::ComfyUI => "comfyui",
        }
    }

    fn rules(self) -> &'static [Rule] {
        match self {
            Self::Claude => CLAUDE,
            Self::Codex => CODEX,
            Self::Copilot => COPILOT,
            Self::ComfyUI => COMFYUI,
        }
    }
}

struct Rule {
    name: &'static str,
    role: &'static str,
    consequence: &'static str,
    evidence: &'static str,
    marker: bool,
}

fn matches_kind(name: &str, kind: ResourceKind) -> bool {
    let file = matches!(
        name,
        "history.jsonl"
            | "settings.json"
            | ".credentials.json"
            | "config.toml"
            | "auth.json"
            | "config.json"
            | "session-store.db"
            | "folder_paths.py"
    );
    kind == if file {
        ResourceKind::File
    } else {
        ResourceKind::Directory
    }
}

const CLAUDE_DOC: &str = "https://code.claude.com/docs/en/claude-directory";
const COPILOT_DOC: &str =
    "https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference";
const CODEX_DOC: &str = "https://github.com/openai/codex/blob/main/codex-rs/core/src/config/mod.rs";
const COMFY_DOC: &str = "https://github.com/Comfy-Org/ComfyUI/blob/master/folder_paths.py";

const CLAUDE: &[Rule] = &[
    Rule {
        name: "projects",
        role: "recoverable_state",
        consequence: "Sessions, project memory and resume history may be lost.",
        evidence: CLAUDE_DOC,
        marker: true,
    },
    Rule {
        name: "history.jsonl",
        role: "recoverable_state",
        consequence: "Prompt recall history may be lost.",
        evidence: CLAUDE_DOC,
        marker: true,
    },
    Rule {
        name: "file-history",
        role: "recoverable_state",
        consequence: "Checkpoint rewind data may be lost.",
        evidence: CLAUDE_DOC,
        marker: false,
    },
    Rule {
        name: "agent-memory",
        role: "user_asset",
        consequence: "Persistent agent memory may be lost.",
        evidence: CLAUDE_DOC,
        marker: false,
    },
    Rule {
        name: "debug",
        role: "logs_or_cache",
        consequence: "Diagnostic logs may be lost.",
        evidence: CLAUDE_DOC,
        marker: false,
    },
    Rule {
        name: "cache",
        role: "logs_or_cache",
        consequence: "Cached data may need to be recreated.",
        evidence: CLAUDE_DOC,
        marker: false,
    },
    Rule {
        name: "settings.json",
        role: "protected_configuration",
        consequence: "Personal settings may be lost.",
        evidence: CLAUDE_DOC,
        marker: true,
    },
    Rule {
        name: ".credentials.json",
        role: "protected_configuration",
        consequence: "Login credentials may be lost.",
        evidence: CLAUDE_DOC,
        marker: false,
    },
];
const CODEX: &[Rule] = &[
    Rule {
        name: "sessions",
        role: "recoverable_state",
        consequence: "Session resume history may be lost.",
        evidence: CODEX_DOC,
        marker: true,
    },
    Rule {
        name: "archived_sessions",
        role: "recoverable_state",
        consequence: "Archived sessions may be lost.",
        evidence: CODEX_DOC,
        marker: false,
    },
    Rule {
        name: "history.jsonl",
        role: "recoverable_state",
        consequence: "Command and prompt history may be lost.",
        evidence: CODEX_DOC,
        marker: false,
    },
    Rule {
        name: "log",
        role: "logs_or_cache",
        consequence: "Diagnostic logs may be lost.",
        evidence: CODEX_DOC,
        marker: false,
    },
    Rule {
        name: "memories",
        role: "user_asset",
        consequence: "Saved memory may be lost.",
        evidence: CODEX_DOC,
        marker: false,
    },
    Rule {
        name: "config.toml",
        role: "protected_configuration",
        consequence: "Personal settings may be lost.",
        evidence: CODEX_DOC,
        marker: true,
    },
    Rule {
        name: "auth.json",
        role: "protected_configuration",
        consequence: "Authentication state may be lost.",
        evidence: CODEX_DOC,
        marker: false,
    },
];
const COPILOT: &[Rule] = &[
    Rule {
        name: "logs",
        role: "logs_or_cache",
        consequence: "Diagnostic logs may be lost.",
        evidence: COPILOT_DOC,
        marker: true,
    },
    Rule {
        name: "session-state",
        role: "recoverable_state",
        consequence: "Local session resume and workspace artifacts may be lost.",
        evidence: COPILOT_DOC,
        marker: true,
    },
    Rule {
        name: "command-history-state",
        role: "recoverable_state",
        consequence: "Command history search may be lost.",
        evidence: COPILOT_DOC,
        marker: false,
    },
    Rule {
        name: "session-store.db",
        role: "recoverable_state",
        consequence: "Cross-session indexing may be lost.",
        evidence: COPILOT_DOC,
        marker: false,
    },
    Rule {
        name: "plugin-data",
        role: "user_asset",
        consequence: "Plugin persistent data may be lost.",
        evidence: COPILOT_DOC,
        marker: false,
    },
    Rule {
        name: "settings.json",
        role: "protected_configuration",
        consequence: "Personal settings may be lost.",
        evidence: COPILOT_DOC,
        marker: true,
    },
    Rule {
        name: "config.json",
        role: "protected_configuration",
        consequence: "Authentication and application state may be lost.",
        evidence: COPILOT_DOC,
        marker: true,
    },
    Rule {
        name: "mcp-secrets",
        role: "protected_configuration",
        consequence: "Secret fallback state may be lost.",
        evidence: COPILOT_DOC,
        marker: false,
    },
];
const COMFYUI: &[Rule] = &[
    Rule {
        name: "folder_paths.py",
        role: "tool_marker",
        consequence: "ComfyUI path configuration source; never a cleanup candidate.",
        evidence: COMFY_DOC,
        marker: true,
    },
    Rule {
        name: "output",
        role: "user_asset",
        consequence: "Generated images and videos may be lost.",
        evidence: COMFY_DOC,
        marker: false,
    },
    Rule {
        name: "input",
        role: "user_asset",
        consequence: "Input media may be lost.",
        evidence: COMFY_DOC,
        marker: false,
    },
    Rule {
        name: "models",
        role: "user_asset",
        consequence: "Model weights may be lost and costly to reacquire.",
        evidence: COMFY_DOC,
        marker: false,
    },
    Rule {
        name: "user",
        role: "recoverable_state",
        consequence: "Workflows and user settings may be lost.",
        evidence: COMFY_DOC,
        marker: false,
    },
    Rule {
        name: "temp",
        role: "logs_or_cache",
        consequence: "In-progress temporary work may be lost.",
        evidence: COMFY_DOC,
        marker: false,
    },
];

#[derive(Serialize)]
pub struct Component {
    pub relative_path: &'static str,
    pub role: &'static str,
    pub consequence: &'static str,
    pub evidence_url: &'static str,
    pub logical_bytes_known: u64,
    pub logical_bytes_unknown_files: u64,
    pub complete: bool,
    pub contains_cloud_placeholder: bool,
}

#[derive(Serialize)]
pub struct Footprint {
    pub schema_version: u32,
    pub kind: &'static str,
    pub tool: &'static str,
    pub rule_version: u32,
    pub recognized: bool,
    pub scan_complete: bool,
    pub logical_bytes_known: u64,
    pub logical_bytes_unknown_files: u64,
    pub components: Vec<Component>,
    pub last_activity: Option<u64>,
    pub running: Option<bool>,
}

/// Projects only exact, documented top-level names from one explicit root.
/// False `recognized` means no ownership claim is made even if names match.
pub fn project(tree: &ScanTree, tool: Tool) -> Option<Footprint> {
    let [root_id] = tree.roots() else { return None };
    let root = tree.entry(*root_id)?;
    if root.kind != ResourceKind::Directory {
        return None;
    }
    let summary = tree.summary(*root_id)?;
    let rules = tool.rules();
    let children = tree.children(*root_id)?;
    let recognized = children.iter().any(|id| {
        tree.entry(*id)
            .and_then(|entry| entry.path.file_name())
            .is_some_and(|name| {
                rules.iter().any(|rule| {
                    rule.marker
                        && name == OsStr::new(rule.name)
                        && tree
                            .entry(*id)
                            .is_some_and(|entry| matches_kind(rule.name, entry.kind))
                })
            })
    });
    let mut components = Vec::new();
    if recognized {
        for rule in rules {
            let Some(entry) = children
                .iter()
                .filter_map(|id| tree.entry(*id))
                .find(|entry| {
                    entry.path.file_name() == Some(OsStr::new(rule.name))
                        && matches_kind(rule.name, entry.kind)
                })
            else {
                continue;
            };
            let (logical_bytes_known, logical_bytes_unknown_files, complete) = match entry.kind {
                ResourceKind::Directory => {
                    let summary = tree.summary(entry.id)?;
                    (
                        summary.logical_bytes_known,
                        summary.logical_bytes_unknown_files,
                        summary.complete,
                    )
                }
                ResourceKind::File => (
                    entry.logical_bytes.unwrap_or(0),
                    u64::from(entry.logical_bytes.is_none()),
                    tree.complete(),
                ),
                ResourceKind::Link | ResourceKind::Other => unreachable!("matched kind"),
            };
            components.push(Component {
                relative_path: rule.name,
                role: rule.role,
                consequence: rule.consequence,
                evidence_url: rule.evidence,
                logical_bytes_known,
                logical_bytes_unknown_files,
                complete,
                contains_cloud_placeholder: tree
                    .report()
                    .entries
                    .iter()
                    .any(|child| child.dataless && child.path.starts_with(&entry.path)),
            });
        }
    }
    Some(Footprint {
        schema_version: 1,
        kind: "ai_footprint",
        tool: tool.code(),
        rule_version: 1,
        recognized,
        scan_complete: summary.complete,
        logical_bytes_known: summary.logical_bytes_known,
        logical_bytes_unknown_files: summary.logical_bytes_unknown_files,
        components,
        last_activity: None,
        running: None,
    })
}
