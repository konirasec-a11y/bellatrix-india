use serde_json::json;

/// Retorna as task definitions do Bellatrix para o Zed task runner.
///
/// O Zed carrega estas tasks do arquivo .zed/tasks.json do projeto.
/// O operador acessa via Cmd+Shift+P → "task: spawn" ou pelo painel de tasks.
pub fn all_tasks() -> serde_json::Value {
    json!([
        // ── Docker stack ───────────────────────────────────────────────────
        docker_task(
            "Bellatrix: Docker Up",
            &["compose", "-f", "docker/compose.yml", "up", "-d"],
            "Start the full Bellatrix security stack"
        ),
        docker_task(
            "Bellatrix: Docker Down",
            &["compose", "-f", "docker/compose.yml", "down"],
            "Stop the full Bellatrix security stack"
        ),
        docker_task(
            "Bellatrix: Docker Health",
            &["compose", "-f", "docker/compose.yml", "ps"],
            "Show health of all Bellatrix containers"
        ),
        docker_task(
            "Bellatrix: Docker Restart",
            &["compose", "-f", "docker/compose.yml", "restart"],
            "Restart all containers"
        ),
        // ── Per-container logs ─────────────────────────────────────────────
        log_task("orchestrator"),
        log_task("semgrep"),
        log_task("nuclei"),
        log_task("caido"),
        log_task("qdrant"),
        log_task("sqlmap"),
        log_task("ffuf"),
        log_task("metasploit"),
        // ── Build ──────────────────────────────────────────────────────────
        cargo_task(
            "Bellatrix: Build (release)",
            &["build", "--release", "--workspace"],
            "Build all workspace crates in release mode"
        ),
        cargo_task(
            "Bellatrix: Test",
            &["test", "--workspace"],
            "Run all workspace tests"
        ),
        cargo_task(
            "Bellatrix: Check",
            &["check", "--workspace"],
            "Type-check all workspace crates"
        ),
        // ── vsc_backend (MCP server) ───────────────────────────────────────
        json!({
            "label": "Bellatrix: Start MCP Backend (local)",
            "command": "cargo",
            "args": ["run", "--bin", "vsc_backend"],
            "env": { "RUST_LOG": "info" },
            "reveal": "always",
            "tags": ["bellatrix", "mcp"],
            "description": "Run vsc_backend MCP server locally (dev mode)"
        }),
        // ── Extension ─────────────────────────────────────────────────────
        json!({
            "label": "Bellatrix: Build Extension (WASM)",
            "command": "cargo",
            "args": [
                "build",
                "--release",
                "--target", "wasm32-wasi",
                "--manifest-path", "extension/Cargo.toml"
            ],
            "env": {},
            "reveal": "always",
            "tags": ["bellatrix", "extension"],
            "description": "Compile the Zed extension to WASM"
        }),
        // ── RAG / data pipeline ────────────────────────────────────────────
        json!({
            "label": "Bellatrix: Ingest RAG Data",
            "command": "bash",
            "args": ["scripts/ingest-rag.sh"],
            "env": {},
            "reveal": "always",
            "tags": ["bellatrix", "rag"],
            "description": "Download and ingest threat intel into Qdrant collections"
        }),
        // ── KVM ────────────────────────────────────────────────────────────
        json!({
            "label": "Bellatrix: KVM List VMs",
            "command": "virsh",
            "args": ["list", "--all"],
            "env": {},
            "reveal": "always",
            "tags": ["bellatrix", "kvm"],
            "description": "List all KVM target VMs"
        }),
        json!({
            "label": "Bellatrix: KVM Snapshot (win10-target)",
            "command": "virsh",
            "args": ["snapshot-create-as", "win10-target", "pre-campaign"],
            "env": {},
            "reveal": "always",
            "tags": ["bellatrix", "kvm"],
            "description": "Create pre-campaign snapshot of Windows 10 target VM"
        }),
        json!({
            "label": "Bellatrix: KVM Restore (win10-target)",
            "command": "virsh",
            "args": ["snapshot-revert", "win10-target", "pre-campaign"],
            "env": {},
            "reveal": "always",
            "tags": ["bellatrix", "kvm"],
            "description": "Restore Windows 10 target VM to clean snapshot"
        }),
    ])
}

fn docker_task(label: &str, args: &[&str], description: &str) -> serde_json::Value {
    json!({
        "label": label,
        "command": "docker",
        "args": args,
        "env": {},
        "reveal": "always",
        "tags": ["bellatrix", "docker"],
        "description": description
    })
}

fn log_task(service: &str) -> serde_json::Value {
    json!({
        "label": format!("Bellatrix: Logs — {}", service),
        "command": "docker",
        "args": ["compose", "-f", "docker/compose.yml", "logs", "-f", "--tail=200", service],
        "env": {},
        "reveal": "always",
        "tags": ["bellatrix", "docker", "logs"],
        "description": format!("Stream logs from {} container", service)
    })
}

fn cargo_task(label: &str, args: &[&str], description: &str) -> serde_json::Value {
    json!({
        "label": label,
        "command": "cargo",
        "args": args,
        "env": { "RUST_BACKTRACE": "1" },
        "reveal": "always",
        "tags": ["bellatrix", "cargo"],
        "description": description
    })
}
