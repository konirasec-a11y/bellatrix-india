use crate::AttackGraph;

/// Renders attack graph as a Mermaid flowchart string for VSCodium webview.
pub fn to_mermaid(graph: &AttackGraph) -> String {
    let json = graph.to_json();
    let mut out = String::from("graph TD\n");

    if let Some(nodes) = json["nodes"].as_array() {
        for (i, node) in nodes.iter().enumerate() {
            let title = node["title"].as_str().unwrap_or("?");
            let severity = node["severity"].as_str().unwrap_or("?");
            out.push_str(&format!("    N{i}[\"{title} [{severity}]\"]\n"));
        }
    }

    if let Some(edges) = json["edges"].as_array() {
        for edge in edges {
            let from = edge["from"].as_u64().unwrap_or(0);
            let to = edge["to"].as_u64().unwrap_or(0);
            out.push_str(&format!("    N{from} --> N{to}\n"));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use application::AttackGraphBuilder;
    use core_domain::{Finding, VulnerabilitySeverity};
    use uuid::Uuid;

    #[test]
    fn test_mermaid_contains_node_titles() {
        let mut graph = AttackGraph::new();
        graph.add_finding(Finding {
            id: Uuid::new_v4(),
            title: "SQL Injection".into(),
            severity: VulnerabilitySeverity::Critical,
            file_path: "db.php".into(),
            line_number: 10,
            taint_trace: None,
            cwe: "CWE-89".into(),
        });

        let mermaid = to_mermaid(&graph);
        assert!(mermaid.contains("SQL Injection"));
        assert!(mermaid.contains("graph TD"));
    }
}
