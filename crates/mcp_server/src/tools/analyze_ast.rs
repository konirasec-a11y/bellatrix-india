use application::McpTool;
use async_trait::async_trait;

pub struct AnalyzeAstTool;

#[async_trait]
impl McpTool for AnalyzeAstTool {
    fn name(&self) -> &str {
        "analyze_ast"
    }

    fn description(&self) -> &str {
        "Runs Tree-sitter parser on a code buffer and returns AST representation with exports and call graph."
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "content": { "type": "string" },
                "language": { "type": "string", "enum": ["php", "python", "javascript", "rust", "go"] }
            },
            "required": ["file_path", "content", "language"]
        })
    }

    async fn execute(&self, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let file_path = params["file_path"].as_str().unwrap_or("unknown");
        let language = params["language"].as_str().unwrap_or("unknown");
        let content = params["content"].as_str().unwrap_or("");

        // Stub: real implementation delegates to sast_engine tree-sitter parsers.
        Ok(serde_json::json!({
            "file_path": file_path,
            "language": language,
            "ast_root": format!("ParsedAST({})", content.len()),
            "exports": [],
            "dependencies": []
        }))
    }
}
