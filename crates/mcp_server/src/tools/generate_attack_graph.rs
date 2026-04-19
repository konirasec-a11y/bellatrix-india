use application::McpTool;
use async_trait::async_trait;

pub struct GenerateAttackGraphTool;

#[async_trait]
impl McpTool for GenerateAttackGraphTool {
    fn name(&self) -> &str {
        "generate_attack_graph"
    }

    fn description(&self) -> &str {
        "Produces a JSON-serialized attack chain graph from a set of findings, using petgraph internally."
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "title": { "type": "string" },
                            "severity": { "type": "string" },
                            "file_path": { "type": "string" },
                            "line_number": { "type": "integer" },
                            "cwe": { "type": "string" }
                        }
                    }
                },
                "target_sink": { "type": "string" }
            },
            "required": ["findings"]
        })
    }

    async fn execute(&self, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        use application::AttackGraphBuilder;
        use attack_graph::AttackGraph;
        use core_domain::{Finding, VulnerabilitySeverity};
        use uuid::Uuid;

        let mut graph = AttackGraph::new();

        if let Some(findings) = params["findings"].as_array() {
            for f in findings {
                let severity = match f["severity"].as_str().unwrap_or("Medium") {
                    "Critical" => VulnerabilitySeverity::Critical,
                    "High" => VulnerabilitySeverity::High,
                    "Low" => VulnerabilitySeverity::Low,
                    "Informational" => VulnerabilitySeverity::Informational,
                    _ => VulnerabilitySeverity::Medium,
                };
                graph.add_finding(Finding {
                    id: Uuid::new_v4(),
                    title: f["title"].as_str().unwrap_or("?").to_string(),
                    severity,
                    file_path: f["file_path"].as_str().unwrap_or("").to_string(),
                    line_number: f["line_number"].as_u64().unwrap_or(0) as u32,
                    taint_trace: None,
                    cwe: f["cwe"].as_str().unwrap_or("").to_string(),
                });
            }
        }

        Ok(graph.to_json())
    }
}
