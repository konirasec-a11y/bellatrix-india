use application::McpTool;
use std::collections::HashMap;
use std::sync::Arc;

pub struct McpRouter {
    tools: HashMap<String, Arc<dyn McpTool>>,
}

impl McpRouter {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, tool: Arc<dyn McpTool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub async fn dispatch(
        &self,
        tool_name: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let tool = self
            .tools
            .get(tool_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown MCP tool: {}", tool_name))?;

        tracing::debug!(tool = tool_name, "dispatching MCP tool");
        tool.execute(params).await
    }

    pub fn list_tools(&self) -> Vec<serde_json::Value> {
        self.tools
            .values()
            .map(|t| {
                serde_json::json!({
                    "name": t.name(),
                    "description": t.description(),
                    "schema": t.schema(),
                })
            })
            .collect()
    }

    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }
}

impl Default for McpRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a fully populated McpRouter with all standard tools.
pub fn build_default_router() -> McpRouter {
    use crate::tools::*;

    let mut router = McpRouter::new();
    router.register(Arc::new(AnalyzeAstTool));
    router.register(Arc::new(TraceTaintTool));
    router.register(Arc::new(SearchThreatIntelTool));
    router.register(Arc::new(GenerateAttackGraphTool));
    router.register(Arc::new(CraftEvasivePayloadTool));
    router.register(Arc::new(GeneratePocTool));
    router.register(Arc::new(SimulateLateralMovementTool));
    router.register(Arc::new(DeployBreakpointTool));
    router
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_router_has_8_tools() {
        let router = build_default_router();
        assert_eq!(router.tool_count(), 8);
    }

    #[tokio::test]
    async fn test_dispatch_unknown_tool_errors() {
        let router = McpRouter::new();
        let result = router.dispatch("nonexistent", serde_json::json!({})).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_list_tools_returns_all() {
        let router = build_default_router();
        let list = router.list_tools();
        assert_eq!(list.len(), 8);

        let names: Vec<&str> = list
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"analyze_ast"));
        assert!(names.contains(&"craft_evasive_payload"));
    }
}
