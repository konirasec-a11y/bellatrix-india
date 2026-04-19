use application::LanguageAnalyzer;
use core_domain::Finding;
use std::sync::Arc;

/// AppSec Analyzer Agent — orchestrates SAST scans across a workspace.
pub struct AppSecAnalyzerAgent {
    analyzer: Arc<dyn LanguageAnalyzer>,
}

impl AppSecAnalyzerAgent {
    pub fn new(analyzer: Arc<dyn LanguageAnalyzer>) -> Self {
        Self { analyzer }
    }

    /// Analyzes a single file and returns findings.
    pub async fn analyze_file(
        &self,
        file_path: &str,
        content: &str,
    ) -> anyhow::Result<Vec<Finding>> {
        if !self.analyzer.handles_language(Self::ext(file_path)) {
            return Ok(vec![]);
        }

        let model = self.analyzer.analyze(file_path, content).await?;
        let sources = self.analyzer.extract_taint_sources(&model).await;

        // Without sast_engine as a dep here, we return a summary finding when sources exist.
        if sources.is_empty() {
            return Ok(vec![]);
        }

        let findings = sources
            .into_iter()
            .map(|src| Finding {
                id: uuid::Uuid::new_v4(),
                title: format!("Potential taint source: {}", src.code_snippet),
                severity: core_domain::VulnerabilitySeverity::Medium,
                file_path: file_path.to_string(),
                line_number: src.line_number,
                taint_trace: None,
                cwe: "CWE-20".to_string(),
            })
            .collect();

        Ok(findings)
    }

    fn ext(path: &str) -> &str {
        path.rsplit('.').next().unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use application::MockLanguageAnalyzer;
    use core_domain::{CodeModel, SourceNode};
    use mockall::predicate::*;

    #[tokio::test]
    async fn test_agent_returns_empty_for_unhandled_language() {
        let mut mock = MockLanguageAnalyzer::new();
        mock.expect_handles_language().return_const(false);

        let agent = AppSecAnalyzerAgent::new(Arc::new(mock));
        let findings = agent.analyze_file("file.go", "package main").await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_agent_returns_findings_for_taint_sources() {
        let mut mock = MockLanguageAnalyzer::new();
        mock.expect_handles_language().with(eq("php")).return_const(true);
        mock.expect_analyze().times(1).returning(|_, _| Ok(CodeModel::default()));
        mock.expect_extract_taint_sources().times(1).returning(|_| {
            vec![SourceNode {
                file_path: "vuln.php".into(),
                line_number: 5,
                code_snippet: "$_GET['cmd']".into(),
            }]
        });

        let agent = AppSecAnalyzerAgent::new(Arc::new(mock));
        let findings = agent
            .analyze_file("vuln.php", "<?php system($_GET['cmd']);")
            .await
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("taint source"));
    }

    #[tokio::test]
    async fn test_agent_returns_empty_when_no_sources() {
        let mut mock = MockLanguageAnalyzer::new();
        mock.expect_handles_language().return_const(true);
        mock.expect_analyze().times(1).returning(|_, _| Ok(CodeModel::default()));
        mock.expect_extract_taint_sources().times(1).returning(|_| vec![]);

        let agent = AppSecAnalyzerAgent::new(Arc::new(mock));
        let findings = agent.analyze_file("safe.php", "<?php echo 'hello';").await.unwrap();
        assert!(findings.is_empty());
    }
}
