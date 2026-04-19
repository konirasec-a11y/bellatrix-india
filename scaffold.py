import os
from pathlib import Path

files = {
    "Cargo.toml": """[workspace]
members = [
    "crates/*"
]
resolver = "2"

[workspace.dependencies]
tokio = { version = "1.36", features = ["full", "macros"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
async-trait = "0.1"
thiserror = "1.0"
anyhow = "1.0"
petgraph = "0.6"
tree-sitter = "0.20"
reqwest = { version = "0.11", features = ["json"] }
mockall = "0.12"
rstest = "0.18"
insta = "1.34"
uuid = { version = "1.6", features = ["v4", "serde"] }
""",
    "crates/core_domain/Cargo.toml": """[package]
name = "core_domain"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { workspace = true }
uuid = { workspace = true }
serde_json = { workspace = true }
""",
    "crates/core_domain/src/lib.rs": """pub mod models;
pub use models::*;
""",
    "crates/core_domain/src/models.rs": """use serde::{Deserialize, Serialize};
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
""",
    "crates/application/Cargo.toml": """[package]
name = "application"
version = "0.1.0"
edition = "2021"

[dependencies]
core_domain = { path = "../core_domain" }
async-trait = { workspace = true }
anyhow = { workspace = true }
serde_json = { workspace = true }
""",
    "crates/application/src/lib.rs": """pub mod ports;
pub use ports::*;
""",
    "crates/application/src/ports.rs": """use async_trait::async_trait;
use core_domain::{Finding, CodeModel, PayloadSpec, SourceNode};
use mockall::automock;

#[automock]
#[async_trait]
pub trait LanguageAnalyzer: Send + Sync {
    fn handles_language(&self, extension: &str) -> bool;
    async fn analyze(&self, file_path: &str, content: &str) -> anyhow::Result<CodeModel>;
    async fn extract_taint_sources(&self, model: &CodeModel) -> Vec<SourceNode>;
}

#[automock]
#[async_trait]
pub trait McpTool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn schema(&self) -> serde_json::Value;
    async fn execute(&self, params: serde_json::Value) -> anyhow::Result<serde_json::Value>;
}

#[automock]
pub trait AttackGraphBuilder {
    fn add_finding(&mut self, finding: Finding);
    fn build_attack_chain(&self, target_sink: &str) -> Option<Vec<Finding>>;
}

#[automock]
#[async_trait]
pub trait EvasionTechnique: Send + Sync {
    fn name(&self) -> &str;
    async fn apply(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>>;
}

#[automock]
#[async_trait]
pub trait PayloadEngine: Send + Sync {
    async fn generate_stager(&self, spec: &PayloadSpec) -> anyhow::Result<Vec<u8>>;
}
""",
    "crates/agents/Cargo.toml": """[package]
name = "agents"
version = "0.1.0"
edition = "2021"

[dependencies]
core_domain = { path = "../core_domain" }
application = { path = "../application" }
tokio = { workspace = true }
anyhow = { workspace = true }
async-trait = { workspace = true }
mockall = { workspace = true }
""",
    "crates/agents/src/lib.rs": """pub mod malware;
""",
    "crates/agents/src/malware/mod.rs": """pub mod agent;
""",
    "crates/agents/src/malware/agent.rs": """use core_domain::PayloadSpec;
use application::PayloadEngine;
use std::sync::Arc;

pub struct MalwareEngineer {
    engine: Arc<dyn PayloadEngine>,
}

impl MalwareEngineer {
    pub fn new(engine: Arc<dyn PayloadEngine>) -> Self {
        Self { engine }
    }

    pub async fn craft_stager(&self, spec: PayloadSpec) -> anyhow::Result<Vec<u8>> {
        self.engine.generate_stager(&spec).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use application::MockPayloadEngine;
    
    #[tokio::test]
    async fn test_agent_crafts_stager_successfully() {
        let mut mock_engine = MockPayloadEngine::new();
        
        mock_engine.expect_generate_stager()
            .withf(|spec| spec.os == "windows" && spec.architecture == "x64" && spec.bypass_amsi == true)
            .times(1)
            .returning(|_| Ok(vec![0x90, 0x90, 0xCC]));

        let agent = MalwareEngineer::new(Arc::new(mock_engine));
        
        let spec = PayloadSpec {
            architecture: "x64".into(),
            os: "windows".into(),
            encoder: None,
            bypass_amsi: true,
            bypass_etw: false,
            bad_chars: vec![0x00],
        };

        let result = agent.craft_stager(spec).await.unwrap();
        assert_eq!(result, vec![0x90, 0x90, 0xCC]);
    }
}
"""
}

for filepath, content in files.items():
    path = Path("/home/administrator/sources/bellatrix-india", filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    print(f"Created {filepath}")
