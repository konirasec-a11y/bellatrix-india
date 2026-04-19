use async_trait::async_trait;
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
