use zed_extension_api::{self as zed};
use serde::Deserialize;

/// Representa um Finding recebido do vsc_backend via MCP.
/// Subset dos campos necessários para criar diagnósticos LSP no Zed.
#[derive(Debug, Deserialize)]
pub struct FindingDigest {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub file_path: String,
    pub line_number: u32,
    pub cwe: String,
    pub message: Option<String>,
}

/// Converte severity string para prefixo de diagnóstico LSP.
pub fn severity_prefix(severity: &str) -> &'static str {
    match severity {
        "Critical" => "🔴 CRITICAL",
        "High" => "🟠 HIGH",
        "Medium" => "🟡 MEDIUM",
        "Low" => "🔵 LOW",
        _ => "⚪ INFO",
    }
}

/// Formata uma mensagem de diagnóstico inline para o Zed editor.
///
/// O Zed mostra esta string como overlay na linha afetada,
/// similar a um erro de compilador ou lint warning.
pub fn format_diagnostic_message(finding: &FindingDigest) -> String {
    let prefix = severity_prefix(&finding.severity);
    let detail = finding.message.as_deref().unwrap_or(&finding.title);
    format!("[Bellatrix] {} — {} ({})", prefix, detail, finding.cwe)
}

/// Serializa um Finding para o formato de diagnóstico LSP esperado pelo Zed.
///
/// O Zed consome isto via o protocolo LSP publicDiagnostics quando o
/// language server adapter repassa os findings da campanha.
pub fn to_lsp_diagnostic(finding: &FindingDigest) -> serde_json::Value {
    let severity_code = match finding.severity.as_str() {
        "Critical" | "High" => 1, // Error
        "Medium" => 2,            // Warning
        "Low" => 3,               // Information
        _ => 4,                   // Hint
    };

    serde_json::json!({
        "range": {
            "start": { "line": finding.line_number.saturating_sub(1), "character": 0 },
            "end": { "line": finding.line_number.saturating_sub(1), "character": 999 }
        },
        "severity": severity_code,
        "code": finding.cwe,
        "source": "bellatrix-india",
        "message": format_diagnostic_message(finding),
        "data": {
            "finding_id": finding.id,
            "title": finding.title,
        }
    })
}

/// Retorna o comando para iniciar o bellatrix_lsp como language server.
///
/// O Zed executa este binário e se comunica via LSP (Content-Length + JSON-RPC 2.0).
/// O binário vigilia .bellatrix/findings.json e envia publishDiagnostics quando
/// o arquivo muda — cada finding vira um overlay colorido no editor.
pub fn lsp_command(
    _language_server_id: &zed::LanguageServerId,
    worktree: &zed::Worktree,
) -> zed::Result<zed::Command> {
    // Procura o binário no PATH do sistema; fallback para nome simples (deve estar no PATH).
    let binary = worktree
        .which("bellatrix_lsp")
        .unwrap_or_else(|| "bellatrix_lsp".to_string());

    Ok(zed::Command {
        command: binary,
        args: vec![],
        env: vec![
            ("BELLATRIX_PROJECT_ROOT".to_string(), worktree.root_path()),
            ("RUST_LOG".to_string(), "warn".to_string()),
        ],
    })
}

/// Agrupa findings por arquivo para envio em lote via LSP textDocument/publishDiagnostics.
pub fn group_by_file(findings: &[FindingDigest]) -> std::collections::HashMap<String, Vec<serde_json::Value>> {
    let mut map: std::collections::HashMap<String, Vec<serde_json::Value>> = std::collections::HashMap::new();
    for f in findings {
        map.entry(f.file_path.clone())
            .or_default()
            .push(to_lsp_diagnostic(f));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(severity: &str, line: u32) -> FindingDigest {
        FindingDigest {
            id: "uuid-test".into(),
            title: "SQL Injection".into(),
            severity: severity.into(),
            file_path: "src/auth.php".into(),
            line_number: line,
            cwe: "CWE-89".into(),
            message: None,
        }
    }

    #[test]
    fn test_critical_maps_to_error_severity() {
        let f = make_finding("Critical", 42);
        let diag = to_lsp_diagnostic(&f);
        assert_eq!(diag["severity"], 1);
    }

    #[test]
    fn test_medium_maps_to_warning() {
        let f = make_finding("Medium", 10);
        let diag = to_lsp_diagnostic(&f);
        assert_eq!(diag["severity"], 2);
    }

    #[test]
    fn test_diagnostic_line_is_zero_based() {
        let f = make_finding("High", 5);
        let diag = to_lsp_diagnostic(&f);
        assert_eq!(diag["range"]["start"]["line"], 4);
    }

    #[test]
    fn test_group_by_file() {
        let findings = vec![
            make_finding("High", 10),
            make_finding("Critical", 20),
        ];
        let grouped = group_by_file(&findings);
        assert_eq!(grouped["src/auth.php"].len(), 2);
    }

    #[test]
    fn test_format_message_includes_cwe() {
        let f = make_finding("High", 1);
        let msg = format_diagnostic_message(&f);
        assert!(msg.contains("CWE-89"));
        assert!(msg.contains("Bellatrix"));
    }
}
