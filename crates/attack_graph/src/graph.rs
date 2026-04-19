use application::AttackGraphBuilder;
use core_domain::{Finding, VulnerabilitySeverity};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

pub struct AttackGraph {
    graph: DiGraph<Finding, String>,
    sink_index: HashMap<String, NodeIndex>,
    source_index: HashMap<String, NodeIndex>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            sink_index: HashMap::new(),
            source_index: HashMap::new(),
        }
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Returns the highest-severity path to a given sink as a serializable JSON value.
    pub fn to_json(&self) -> serde_json::Value {
        let nodes: Vec<serde_json::Value> = self
            .graph
            .node_indices()
            .map(|i| {
                let f = &self.graph[i];
                serde_json::json!({
                    "id": f.id,
                    "title": f.title,
                    "severity": format!("{:?}", f.severity),
                    "file": f.file_path,
                    "line": f.line_number,
                    "cwe": f.cwe,
                })
            })
            .collect();

        let edges: Vec<serde_json::Value> = self
            .graph
            .edge_indices()
            .map(|e| {
                let (src, dst) = self.graph.edge_endpoints(e).unwrap();
                serde_json::json!({ "from": src.index(), "to": dst.index() })
            })
            .collect();

        serde_json::json!({ "nodes": nodes, "edges": edges })
    }

    fn sink_key(finding: &Finding) -> String {
        format!("{}:{}", finding.file_path, finding.line_number)
    }

    fn source_key(finding: &Finding) -> String {
        finding.id.to_string()
    }

    fn severity_rank(s: &VulnerabilitySeverity) -> u8 {
        match s {
            VulnerabilitySeverity::Critical => 5,
            VulnerabilitySeverity::High => 4,
            VulnerabilitySeverity::Medium => 3,
            VulnerabilitySeverity::Low => 2,
            VulnerabilitySeverity::Informational => 1,
        }
    }
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGraphBuilder for AttackGraph {
    fn add_finding(&mut self, finding: Finding) {
        let sink_key = Self::sink_key(&finding);
        let source_key = Self::source_key(&finding);

        let node_idx = self.graph.add_node(finding);
        self.sink_index.insert(sink_key, node_idx);
        self.source_index.insert(source_key, node_idx);

        // Wire edges: if this finding's taint trace references a prior sink, add edge.
        let taint_source = self.graph[node_idx]
            .taint_trace
            .as_ref()
            .map(|t| format!("{}:{}", t.source.file_path, t.source.line_number));

        if let Some(src_key) = taint_source {
            if let Some(&predecessor) = self.sink_index.get(&src_key) {
                self.graph.add_edge(predecessor, node_idx, "taint".to_string());
            }
        }
    }

    fn build_attack_chain(&self, target_sink: &str) -> Option<Vec<Finding>> {
        let &sink_node = self.sink_index.get(target_sink)?;

        use petgraph::algo::all_simple_paths;
        let roots: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&n| {
                self.graph
                    .neighbors_directed(n, petgraph::Direction::Incoming)
                    .count()
                    == 0
            })
            .collect();

        let mut best: Option<Vec<Finding>> = None;
        let mut best_score = 0u32;

        for root in roots {
            let paths: Vec<Vec<NodeIndex>> =
                all_simple_paths(&self.graph, root, sink_node, 0, None).collect();

            for path in paths {
                let score: u32 = path
                    .iter()
                    .map(|&n| Self::severity_rank(&self.graph[n].severity) as u32)
                    .sum();

                if score > best_score {
                    best_score = score;
                    best = Some(path.iter().map(|&n| self.graph[n].clone()).collect());
                }
            }
        }

        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_domain::{Finding, VulnerabilitySeverity};
    use uuid::Uuid;

    fn make_finding(title: &str, severity: VulnerabilitySeverity, file: &str, line: u32) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            title: title.into(),
            severity,
            file_path: file.into(),
            line_number: line,
            taint_trace: None,
            cwe: "CWE-0".into(),
        }
    }

    #[test]
    fn test_add_finding_increments_node_count() {
        let mut graph = AttackGraph::new();
        assert_eq!(graph.node_count(), 0);

        graph.add_finding(make_finding("XSS", VulnerabilitySeverity::High, "app.js", 10));
        assert_eq!(graph.node_count(), 1);

        graph.add_finding(make_finding("SQLi", VulnerabilitySeverity::Critical, "db.php", 20));
        assert_eq!(graph.node_count(), 2);
    }

    #[test]
    fn test_build_attack_chain_returns_none_for_missing_sink() {
        let graph = AttackGraph::new();
        assert!(graph.build_attack_chain("nonexistent:0").is_none());
    }

    #[test]
    fn test_to_json_structure() {
        let mut graph = AttackGraph::new();
        graph.add_finding(make_finding("RCE", VulnerabilitySeverity::Critical, "cmd.php", 5));
        let json = graph.to_json();
        assert!(json["nodes"].is_array());
        assert_eq!(json["nodes"].as_array().unwrap().len(), 1);
    }
}
