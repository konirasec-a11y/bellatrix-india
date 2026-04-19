/// Cross-crate integration tests covering the full pipeline.
use application::{AttackGraphBuilder, PayloadEngine};
use core_domain::{Finding, PayloadSpec, VulnerabilitySeverity};
use uuid::Uuid;

// ── SCA Engine ───────────────────────────────────────────────────────────────

#[test]
fn sca_detects_log4shell() {
    use sca_engine::{AdvisoryDatabase, ScaScanner};
    use sca_engine::scanner::Dependency;

    let db = AdvisoryDatabase::with_defaults();
    let scanner = ScaScanner::new(db);
    let deps = vec![Dependency { name: "log4j".into(), version: "2.14.1".into() }];
    let findings = scanner.scan(&deps);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, VulnerabilitySeverity::Critical);
}

// ── Attack Graph ─────────────────────────────────────────────────────────────

#[test]
fn attack_graph_builds_from_findings() {
    use attack_graph::AttackGraph;

    let mut graph = AttackGraph::new();

    let findings = vec![
        Finding {
            id: Uuid::new_v4(),
            title: "XSS".into(),
            severity: VulnerabilitySeverity::High,
            file_path: "views/index.php".into(),
            line_number: 10,
            taint_trace: None,
            cwe: "CWE-79".into(),
        },
        Finding {
            id: Uuid::new_v4(),
            title: "SQLi".into(),
            severity: VulnerabilitySeverity::Critical,
            file_path: "models/user.php".into(),
            line_number: 42,
            taint_trace: None,
            cwe: "CWE-89".into(),
        },
    ];

    for f in findings {
        graph.add_finding(f);
    }

    assert_eq!(graph.node_count(), 2);

    let json = graph.to_json();
    let nodes = json["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
}

// ── Malware Crafter ──────────────────────────────────────────────────────────

#[tokio::test]
async fn malware_crafter_pipeline_amsi_etw() {
    use malware_crafter::MalwareCraftingEngine;

    let spec = PayloadSpec {
        os: "windows".into(),
        architecture: "x64".into(),
        bypass_amsi: true,
        bypass_etw: true,
        encoder: None,
        bad_chars: vec![],
    };

    let engine = MalwareCraftingEngine::from_spec(&spec);
    let payload = engine.generate_stager(&spec).await.unwrap();

    // Pipeline order: AMSI first, then ETW — ETW prepends 0xC3 (RET) last.
    assert_eq!(payload[0], 0xC3, "ETW blocker RET expected as outermost byte");
    assert!(payload.len() > 7, "payload must include both stubs and base shellcode");
}

#[tokio::test]
async fn malware_crafter_xor_encodes_payload() {
    use malware_crafter::MalwareCraftingEngine;

    let spec = PayloadSpec {
        os: "linux".into(),
        architecture: "x64".into(),
        bypass_amsi: false,
        bypass_etw: false,
        encoder: Some("xor".into()),
        bad_chars: vec![],
    };

    let engine = MalwareCraftingEngine::from_spec(&spec);
    let payload = engine.generate_stager(&spec).await.unwrap();
    assert!(!payload.is_empty());
}

// ── MCP Router ───────────────────────────────────────────────────────────────

#[test]
fn mcp_router_exposes_all_8_tools() {
    let router = mcp_server::router::build_default_router();
    assert_eq!(router.tool_count(), 8);
}

#[tokio::test]
async fn mcp_craft_payload_tool_returns_hex() {
    let router = mcp_server::router::build_default_router();
    let result = router
        .dispatch(
            "craft_evasive_payload",
            serde_json::json!({ "target_os": "linux", "arch": "x64" }),
        )
        .await
        .unwrap();

    assert!(result["payload_hex"].is_string());
    assert!(result["size_bytes"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn mcp_generate_attack_graph_tool_roundtrips() {
    let router = mcp_server::router::build_default_router();
    let result = router
        .dispatch(
            "generate_attack_graph",
            serde_json::json!({
                "findings": [
                    { "title": "RCE", "severity": "Critical", "file_path": "app.php", "line_number": 5, "cwe": "CWE-78" }
                ]
            }),
        )
        .await
        .unwrap();

    assert_eq!(result["nodes"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn mcp_deploy_breakpoint_produces_launch_json() {
    let router = mcp_server::router::build_default_router();
    let result = router
        .dispatch(
            "deploy_breakpoint",
            serde_json::json!({ "file_path": "sink.php", "sink_lines": [42, 99] }),
        )
        .await
        .unwrap();

    assert_eq!(result["breakpoint_count"].as_u64().unwrap(), 2);
    assert!(result["launch_json"]["configurations"].is_array());
}

#[tokio::test]
async fn mcp_generate_poc_sqli() {
    let router = mcp_server::router::build_default_router();
    let result = router
        .dispatch(
            "generate_poc",
            serde_json::json!({
                "finding_id": "abc123",
                "cwe": "CWE-89",
                "target_url": "http://target/search",
                "language": "curl"
            }),
        )
        .await
        .unwrap();

    let script = result["script"].as_str().unwrap();
    assert!(script.contains("OR 1=1"));
}
