use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    pub package: String,
    pub affected_versions: Vec<String>,
    pub severity: String,
    pub description: String,
    pub cvss_score: Option<f32>,
}

/// In-memory advisory database (production would load from OSV/Grype feeds).
pub struct AdvisoryDatabase {
    advisories: HashMap<String, Vec<Advisory>>,
}

impl AdvisoryDatabase {
    pub fn new() -> Self {
        Self {
            advisories: HashMap::new(),
        }
    }

    /// Seed with well-known critical advisories for demonstration/test.
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        db.insert(Advisory {
            id: "GHSA-0001".into(),
            package: "log4j".into(),
            affected_versions: vec!["2.0.0".into(), "2.14.1".into()],
            severity: "Critical".into(),
            description: "Log4Shell RCE via JNDI injection".into(),
            cvss_score: Some(10.0),
        });
        db.insert(Advisory {
            id: "GHSA-0002".into(),
            package: "lodash".into(),
            affected_versions: vec!["4.17.15".into()],
            severity: "High".into(),
            description: "Prototype pollution via merge".into(),
            cvss_score: Some(7.4),
        });
        db
    }

    pub fn insert(&mut self, advisory: Advisory) {
        self.advisories
            .entry(advisory.package.clone())
            .or_default()
            .push(advisory);
    }

    pub fn lookup(&self, package: &str, version: &str) -> Vec<&Advisory> {
        self.advisories
            .get(package)
            .map(|list| {
                list.iter()
                    .filter(|a| a.affected_versions.iter().any(|v| v == version))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for AdvisoryDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advisory_lookup_finds_known_vuln() {
        let db = AdvisoryDatabase::with_defaults();
        let results = db.lookup("log4j", "2.14.1");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "GHSA-0001");
    }

    #[test]
    fn test_advisory_lookup_miss() {
        let db = AdvisoryDatabase::with_defaults();
        let results = db.lookup("log4j", "2.17.0");
        assert!(results.is_empty());
    }

    #[test]
    fn test_advisory_lookup_unknown_package() {
        let db = AdvisoryDatabase::with_defaults();
        let results = db.lookup("unknown-pkg", "1.0.0");
        assert!(results.is_empty());
    }
}
