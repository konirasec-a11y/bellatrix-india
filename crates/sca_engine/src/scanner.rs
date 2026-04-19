use crate::advisory::{Advisory, AdvisoryDatabase};
use core_domain::{Finding, VulnerabilitySeverity};
use uuid::Uuid;

#[derive(Debug)]
pub struct Dependency {
    pub name: String,
    pub version: String,
}

pub struct ScaScanner {
    db: AdvisoryDatabase,
}

impl ScaScanner {
    pub fn new(db: AdvisoryDatabase) -> Self {
        Self { db }
    }

    pub fn scan(&self, dependencies: &[Dependency]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for dep in dependencies {
            let advisories = self.db.lookup(&dep.name, &dep.version);
            for advisory in advisories {
                findings.push(self.advisory_to_finding(dep, advisory));
            }
        }

        findings
    }

    fn advisory_to_finding(&self, dep: &Dependency, advisory: &Advisory) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            title: format!("{}: {} ({})", advisory.id, dep.name, dep.version),
            severity: self.map_severity(&advisory.severity),
            file_path: "Cargo.lock".to_string(),
            line_number: 0,
            taint_trace: None,
            cwe: format!("CVE/{}", advisory.id),
        }
    }

    fn map_severity(&self, s: &str) -> VulnerabilitySeverity {
        match s {
            "Critical" => VulnerabilitySeverity::Critical,
            "High" => VulnerabilitySeverity::High,
            "Medium" => VulnerabilitySeverity::Medium,
            "Low" => VulnerabilitySeverity::Low,
            _ => VulnerabilitySeverity::Informational,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::AdvisoryDatabase;
    use core_domain::VulnerabilitySeverity;

    #[test]
    fn test_scanner_finds_critical_vulnerability() {
        let db = AdvisoryDatabase::with_defaults();
        let scanner = ScaScanner::new(db);

        let deps = vec![Dependency {
            name: "log4j".into(),
            version: "2.14.1".into(),
        }];

        let findings = scanner.scan(&deps);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, VulnerabilitySeverity::Critical);
    }

    #[test]
    fn test_scanner_no_findings_for_safe_deps() {
        let db = AdvisoryDatabase::with_defaults();
        let scanner = ScaScanner::new(db);

        let deps = vec![Dependency {
            name: "tokio".into(),
            version: "1.36.0".into(),
        }];

        let findings = scanner.scan(&deps);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scanner_multiple_deps() {
        let db = AdvisoryDatabase::with_defaults();
        let scanner = ScaScanner::new(db);

        let deps = vec![
            Dependency { name: "log4j".into(), version: "2.14.1".into() },
            Dependency { name: "lodash".into(), version: "4.17.15".into() },
            Dependency { name: "tokio".into(), version: "1.36.0".into() },
        ];

        let findings = scanner.scan(&deps);
        assert_eq!(findings.len(), 2);
    }
}
