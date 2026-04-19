use application::LanguageAnalyzer;
use core_domain::Finding;
use std::sync::Arc;

pub struct SastOrchestrator {
    analyzers: Vec<Arc<dyn LanguageAnalyzer>>,
}

impl SastOrchestrator {
    pub fn new(analyzers: Vec<Arc<dyn LanguageAnalyzer>>) -> Self {
        Self { analyzers }
    }

    pub fn add_analyzer(&mut self, analyzer: Arc<dyn LanguageAnalyzer>) {
        self.analyzers.push(analyzer);
    }

    pub async fn run_scan(&self, file_path: &str, content: &str) -> anyhow::Result<Vec<Finding>> {
        let ext = file_path.rsplit('.').next().unwrap_or("");

        for analyzer in &self.analyzers {
            if analyzer.handles_language(ext) {
                tracing::debug!(file_path, ext, "routing to analyzer");
                let model = analyzer.analyze(file_path, content).await?;
                let sources = analyzer.extract_taint_sources(&model).await;
                let tracker = crate::taint::TaintTracker::new(sources);
                return tracker.scan_findings(file_path, &model);
            }
        }

        tracing::warn!(file_path, "no analyzer found for extension");
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use application::MockLanguageAnalyzer;
    use core_domain::CodeModel;
    use mockall::predicate::*;

    #[tokio::test]
    async fn test_orchestrator_routes_to_correct_language_analyzer() {
        let mut mock_php = MockLanguageAnalyzer::new();
        mock_php
            .expect_handles_language()
            .with(eq("php"))
            .return_const(true);
        mock_php
            .expect_handles_language()
            .with(ne("php"))
            .return_const(false);
        mock_php
            .expect_analyze()
            .times(1)
            .returning(|_, _| Ok(CodeModel {
                language: "php".into(),
                ast_root: "".into(),
                exports: vec![],
                dependencies: vec![],
            }));
        mock_php
            .expect_extract_taint_sources()
            .times(1)
            .returning(|_| vec![]);

        let mut mock_rust = MockLanguageAnalyzer::new();
        mock_rust.expect_handles_language().return_const(false);

        let orchestrator = SastOrchestrator::new(vec![
            Arc::new(mock_php),
            Arc::new(mock_rust),
        ]);

        let findings = orchestrator
            .run_scan("target.php", "<?php system($_GET['cmd']);")
            .await
            .unwrap();

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_orchestrator_returns_empty_for_unknown_extension() {
        let mut mock = MockLanguageAnalyzer::new();
        mock.expect_handles_language().return_const(false);

        let orchestrator = SastOrchestrator::new(vec![Arc::new(mock)]);
        let findings = orchestrator.run_scan("file.xyz", "content").await.unwrap();
        assert!(findings.is_empty());
    }
}
