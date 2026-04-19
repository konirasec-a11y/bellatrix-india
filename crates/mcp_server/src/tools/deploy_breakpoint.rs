use application::McpTool;
use async_trait::async_trait;

pub struct DeployBreakpointTool;

#[async_trait]
impl McpTool for DeployBreakpointTool {
    fn name(&self) -> &str {
        "deploy_breakpoint"
    }

    fn description(&self) -> &str {
        "Generates a .vscode/launch.json with precise breakpoints at sink lines for interactive debugging."
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "sink_lines": {
                    "type": "array",
                    "items": { "type": "integer" }
                },
                "program": { "type": "string" }
            },
            "required": ["file_path", "sink_lines"]
        })
    }

    async fn execute(&self, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let file_path = params["file_path"].as_str().unwrap_or("unknown");
        let program = params["program"].as_str().unwrap_or("${workspaceFolder}/target/debug/app");

        let sink_lines: Vec<u64> = params["sink_lines"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
            .unwrap_or_default();

        let breakpoints: Vec<serde_json::Value> = sink_lines
            .iter()
            .map(|&line| {
                serde_json::json!({
                    "line": line,
                    "source": { "path": file_path }
                })
            })
            .collect();

        let launch_config = serde_json::json!({
            "version": "0.2.0",
            "configurations": [{
                "type": "lldb",
                "request": "launch",
                "name": "Bellatrix: Debug Sink",
                "program": program,
                "stopOnEntry": false,
                "breakpoints": breakpoints
            }]
        });

        Ok(serde_json::json!({
            "launch_json": launch_config,
            "breakpoint_count": breakpoints.len(),
            "file": file_path
        }))
    }
}
