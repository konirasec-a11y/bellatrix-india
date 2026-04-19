use application::McpTool;
use async_trait::async_trait;

pub struct SimulateLateralMovementTool;

#[async_trait]
impl McpTool for SimulateLateralMovementTool {
    fn name(&self) -> &str {
        "simulate_lateral_movement"
    }

    fn description(&self) -> &str {
        "Analyzes local network connections and IAM roles to generate a lateral movement possibility matrix."
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "network_interfaces": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "iam_roles": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "pivot_host": { "type": "string" }
            },
            "required": []
        })
    }

    async fn execute(&self, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let interfaces = params["network_interfaces"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        let iam_roles = params["iam_roles"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        let pivot = params["pivot_host"].as_str().unwrap_or("local");

        let matrix: Vec<serde_json::Value> = interfaces
            .iter()
            .map(|iface| {
                serde_json::json!({
                    "from": pivot,
                    "via_interface": iface,
                    "reachable_segments": ["10.0.0.0/8", "172.16.0.0/12"],
                    "technique": "T1021 - Remote Services"
                })
            })
            .chain(iam_roles.iter().map(|role| {
                serde_json::json!({
                    "from": pivot,
                    "via_iam_role": role,
                    "possible_actions": ["sts:AssumeRole", "ec2:DescribeInstances"],
                    "technique": "T1078.004 - Cloud Accounts"
                })
            }))
            .collect();

        Ok(serde_json::json!({
            "pivot_host": pivot,
            "movement_matrix": matrix
        }))
    }
}
