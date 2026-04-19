use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnerabilitySeverity {
    Critical, High, Medium, Low, Informational
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub title: String,
    pub severity: VulnerabilitySeverity,
    pub file_path: String,
    pub line_number: u32,
    pub taint_trace: Option<TaintTrace>,
    pub cwe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintTrace {
    pub source: SourceNode,
    pub sink: SinkNode,
    pub hops: Vec<HopNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceNode {
    pub file_path: String,
    pub line_number: u32,
    pub code_snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkNode {
    pub file_path: String,
    pub line_number: u32,
    pub code_snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopNode {
    pub file_path: String,
    pub line_number: u32,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeModel {
    pub language: String,
    pub ast_root: String,
    pub exports: Vec<String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PayloadSpec {
    pub architecture: String,
    pub os: String,
    pub encoder: Option<String>,
    pub bypass_amsi: bool,
    pub bypass_etw: bool,
    pub bad_chars: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_creation() {
        let finding = Finding {
            id: Uuid::new_v4(),
            title: "SQL Injection".into(),
            severity: VulnerabilitySeverity::Critical,
            file_path: "src/auth.php".into(),
            line_number: 42,
            taint_trace: None,
            cwe: "CWE-89".into(),
        };
        assert_eq!(finding.severity, VulnerabilitySeverity::Critical);
    }
}
