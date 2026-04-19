use core_domain::{CodeModel, Finding, SourceNode, TaintTrace, SinkNode, VulnerabilitySeverity};
use uuid::Uuid;

/// Tracks taint flows from sources to potential sinks.
pub struct TaintTracker {
    sources: Vec<SourceNode>,
}

impl TaintTracker {
    pub fn new(sources: Vec<SourceNode>) -> Self {
        Self { sources }
    }

    /// Produces Findings by correlating sources against known dangerous patterns.
    pub fn scan_findings(&self, file_path: &str, model: &CodeModel) -> anyhow::Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for source in &self.sources {
            if let Some(sink) = self.detect_sink_in_model(model, &source.code_snippet) {
                findings.push(Finding {
                    id: Uuid::new_v4(),
                    title: format!("Taint flow from user input to dangerous sink in {}", model.language),
                    severity: VulnerabilitySeverity::High,
                    file_path: file_path.to_string(),
                    line_number: sink.line_number,
                    cwe: "CWE-20".to_string(),
                    taint_trace: Some(TaintTrace {
                        source: source.clone(),
                        sink,
                        hops: vec![],
                    }),
                });
            }
        }

        Ok(findings)
    }

    fn detect_sink_in_model(&self, model: &CodeModel, _source_snippet: &str) -> Option<SinkNode> {
        let dangerous_patterns = ["system(", "exec(", "eval(", "shell_exec(", "popen("];

        for pattern in &dangerous_patterns {
            if model.ast_root.contains(pattern) {
                return Some(SinkNode {
                    file_path: "unknown".to_string(),
                    line_number: 0,
                    code_snippet: pattern.to_string(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_tracker_detects_sink() {
        let source = SourceNode {
            file_path: "input.php".into(),
            line_number: 1,
            code_snippet: "$_GET['cmd']".into(),
        };

        let model = CodeModel {
            language: "php".into(),
            ast_root: "system($_GET['cmd'])".into(),
            exports: vec![],
            dependencies: vec![],
        };

        let tracker = TaintTracker::new(vec![source]);
        let findings = tracker.scan_findings("input.php", &model).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, VulnerabilitySeverity::High);
    }

    #[test]
    fn test_taint_tracker_no_sink_returns_empty() {
        let source = SourceNode {
            file_path: "safe.php".into(),
            line_number: 1,
            code_snippet: "$_GET['name']".into(),
        };

        let model = CodeModel {
            language: "php".into(),
            ast_root: "echo htmlspecialchars($name)".into(),
            exports: vec![],
            dependencies: vec![],
        };

        let tracker = TaintTracker::new(vec![source]);
        let findings = tracker.scan_findings("safe.php", &model).unwrap();
        assert!(findings.is_empty());
    }
}
