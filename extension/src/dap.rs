/// Configurações de debug DAP para targets em Docker e VMs KVM.
///
/// O Zed usa DAP (Debug Adapter Protocol) para debugar processos.
/// A extensão gera configurações launch.json que o Zed pode carregar
/// para conectar o debugger a processos dentro de containers Docker
/// ou VMs KVM.

use serde::Serialize;

/// Tipo de target a debugar.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DebugTarget {
    /// Processo Rust rodando dentro do container orchestrator
    DockerRust {
        container: String,
        binary: String,
    },
    /// Processo nativo no host ou VM KVM via SSH
    RemoteSsh {
        host: String,
        port: u16,
        binary: String,
    },
    /// Attach a processo já rodando (por PID)
    AttachPid {
        pid: u32,
    },
}

/// Gera configuração DAP para o Zed debugar binários Rust em Docker.
///
/// O Zed lê este JSON e configura o DAP adapter (CodeLLDB ou similar)
/// para se conectar ao processo dentro do container via port forwarding.
pub fn docker_rust_config(container: &str, binary: &str, source_root: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "lldb",
        "request": "attach",
        "name": format!("Bellatrix: Debug {} in Docker", binary),
        "pid": "${command:pickProcess}",
        "sourceMap": {
            "/app": source_root
        },
        "initCommands": [
            // Conecta ao processo dentro do container via /proc/[pid]
            format!("settings set target.source-map /app {}", source_root)
        ],
        "postRunCommands": [],
        "cargo": {
            "args": ["build", "--manifest-path", format!("{}/Cargo.toml", source_root)]
        }
    })
}

/// Gera configuração DAP para debugar aplicações web alvo em VMs KVM.
///
/// Usa remote debugging via gdbserver/lldb-server na VM.
/// A VM deve ter o debug server configurado (veja scripts/setup-kvm.sh).
pub fn kvm_remote_config(vm_ip: &str, debug_port: u16, binary: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "gdb",
        "request": "attach",
        "name": format!("Bellatrix: Remote Debug {} @ {}:{}", binary, vm_ip, debug_port),
        "remote": true,
        "address": format!("{}:{}", vm_ip, debug_port),
        "executable": binary,
        "cwd": "${workspaceFolder}"
    })
}

/// Gera breakpoints para os sinks encontrados em uma campanha.
///
/// Retorna o JSON de .zed/debug.json que o Zed carrega automaticamente.
/// Cada sink vira um breakpoint na linha exata — o operador verifica
/// o estado da aplicação no momento do taint flow.
pub fn breakpoints_from_findings(findings: &[crate::diagnostics::FindingDigest]) -> serde_json::Value {
    let breakpoints: Vec<serde_json::Value> = findings
        .iter()
        .filter(|f| matches!(f.severity.as_str(), "Critical" | "High"))
        .map(|f| {
            serde_json::json!({
                "file": f.file_path,
                "line": f.line_number,
                "condition": null,
                "log_message": format!("[Bellatrix] {} hit — {} ({})", f.severity, f.title, f.cwe)
            })
        })
        .collect();

    serde_json::json!({
        "version": "0.2.0",
        "breakpoints": breakpoints
    })
}
