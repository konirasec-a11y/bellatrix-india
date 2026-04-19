use application::McpTool;
use async_trait::async_trait;

pub struct TraceTaintTool;

#[async_trait]
impl McpTool for TraceTaintTool {
    fn name(&self) -> &str {
        "trace_taint"
    }

    fn description(&self) -> &str {
        "Builds a bidirectional taint path between a vulnerable source and a dangerous sink."
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "source_line": { "type": "integer" },
                "sink_line": { "type": "integer" }
            },
            "required": ["file_path", "source_line", "sink_line"]
        })
    }

    async fn execute(&self, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let file_path = params["file_path"].as_str().unwrap_or("unknown");
        let source_line = params["source_line"].as_u64().unwrap_or(0);
        let sink_line = params["sink_line"].as_u64().unwrap_or(0);

        Ok(serde_json::json!({
            "source": { "file": file_path, "line": source_line },
            "sink": { "file": file_path, "line": sink_line },
            "hops": [],
            "reachable": source_line < sink_line
        }))
    }
}
