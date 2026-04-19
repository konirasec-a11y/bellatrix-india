use zed_extension_api::{self as zed, SlashCommand, SlashCommandOutput, SlashCommandOutputSection};

/// Despacha subcomandos /bellatrix para seus handlers.
pub fn run(
    command: SlashCommand,
    args: Vec<String>,
    worktree: Option<&zed::Worktree>,
) -> Result<SlashCommandOutput, String> {
    let subcommand = args.first().map(String::as_str).unwrap_or("help");
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();

    match subcommand {
        "scan" => handle_scan(&rest, worktree),
        "campaign" => handle_campaign(&rest),
        "report" => handle_report(),
        "intel" => handle_intel(&rest),
        "status" => handle_status(),
        "docker" => handle_docker(&rest),
        "debug" => handle_debug(&rest),
        _ => handle_help(),
    }
}

fn output(text: String, label: &str) -> Result<SlashCommandOutput, String> {
    let len = text.len();
    Ok(SlashCommandOutput {
        text,
        sections: vec![SlashCommandOutputSection {
            range: 0..len,
            label: label.to_string(),
        }],
    })
}

// ── Handlers ───────────────────────────────────────────────────────────────

fn handle_scan(args: &[&str], worktree: Option<&zed::Worktree>) -> Result<SlashCommandOutput, String> {
    let path = args
        .first()
        .map(|s| s.to_string())
        .or_else(|| worktree.map(|w| w.root_path()))
        .unwrap_or_else(|| ".".to_string());

    let prompt = format!(
        "Use the `sast_scan` MCP tool to analyze `{}` for security vulnerabilities.\n\
         Focus on: SQLi, CMDi, XSS, Path Traversal, SSRF, Deserialization, Auth Bypass.\n\
         For each finding:\n\
         - Show severity, file:line, CWE\n\
         - Use `trace_taint` to map source → sink for Critical/High findings\n\
         - Use `generate_poc` to create a PoC script\n\
         Format findings as: [SEVERITY] title — file:line (CWE-XX)",
        path
    );
    output(prompt, &format!("SAST: {}", path))
}

fn handle_campaign(args: &[&str]) -> Result<SlashCommandOutput, String> {
    let target = args.first().copied().unwrap_or("[URL or domain]");
    let prompt = format!(
        "Start a Bellatrix AppSec campaign against `{}`:\n\
         1. `analyze_ast` on available source code\n\
         2. Subdomain enum + HTTP probe (`subfinder` → `httpx`)\n\
         3. Tech fingerprint → RAG query for known CVEs\n\
         4. `vuln_scan` with Nuclei (match tech stack)\n\
         5. Test OWASP Top 10: SQLi, XSS, SSRF, IDOR, Auth Bypass\n\
         6. `generate_poc` for each confirmed finding\n\
         7. `generate_attack_graph` from all findings\n\
         Report every confirmed finding with CVSS + reproduction steps.",
        target
    );
    output(prompt, &format!("Campaign: {}", target))
}

fn handle_report() -> Result<SlashCommandOutput, String> {
    let prompt = "Generate HackerOne vulnerability reports for current campaign findings.\n\
         For each finding (sorted by CVSS desc):\n\
         1. Title (≤200 chars)\n\
         2. CVSS 3.1 score + vector string\n\
         3. Vulnerability information (description, root cause, impact)\n\
         4. Numbered steps to reproduce with HTTP request/response\n\
         5. PoC script from `generate_poc`\n\
         6. Business impact analysis\n\
         7. Specific remediation with code example\n\
         Format in HackerOne markdown.";
    output(prompt.to_string(), "Report: HackerOne Format")
}

fn handle_intel(args: &[&str]) -> Result<SlashCommandOutput, String> {
    let query = if args.is_empty() {
        "recent critical CVEs web frameworks".to_string()
    } else {
        args.join(" ")
    };
    let prompt = format!(
        "Use `search_threat_intel` to query RAG for: \"{}\"\n\
         Search: CVE database, MITRE ATT&CK, APT playbooks, LOLBAS, OWASP.\n\
         Format:\n\
         - CVEs: ID, CVSS, affected versions, exploit status\n\
         - TTPs: ID, tactic, description, detection hints\n\
         - LOLBAS: binary, platform, abuse method, ATT&CK mapping",
        query
    );
    output(prompt, &format!("Intel: {}", query))
}

fn handle_status() -> Result<SlashCommandOutput, String> {
    let prompt = "Bellatrix campaign status summary:\n\
         - Campaign name, target, service type, elapsed time\n\
         - Phases completed vs remaining (PTES)\n\
         - Finding count by severity\n\
         - Docker stack health (all containers running?)\n\
         - Tools executed and outcomes\n\
         - Next planned actions\n\
         - Any errors or blockers";
    output(prompt.to_string(), "Campaign Status")
}

fn handle_docker(args: &[&str]) -> Result<SlashCommandOutput, String> {
    let action = args.first().copied().unwrap_or("status");
    let prompt = match action {
        "up" => "Start the Bellatrix Docker stack. Run:\n\
                 `docker compose -f docker/compose.yml up -d`\n\
                 Then verify all containers are healthy:\n\
                 `docker compose -f docker/compose.yml ps`\n\
                 Report which containers started successfully and which failed.",
        "down" => "Stop the Bellatrix Docker stack:\n\
                   `docker compose -f docker/compose.yml down`\n\
                   Confirm all containers stopped.",
        "logs" => {
            let service = args.get(1).copied().unwrap_or("orchestrator");
            &format!("Show recent logs for the `{}` container:\n\
                     `docker compose -f docker/compose.yml logs --tail=100 {}`",
                     service, service)
        }
        "health" => "Check health of all Bellatrix containers:\n\
                     `docker compose -f docker/compose.yml ps`\n\
                     Report: which are running, which are unhealthy, restart any failed ones.",
        _ => "Docker management commands:\n\
              `/bellatrix docker up` — start full stack\n\
              `/bellatrix docker down` — stop stack\n\
              `/bellatrix docker logs [service]` — view container logs\n\
              `/bellatrix docker health` — check all containers",
    };
    output(prompt.to_string(), &format!("Docker: {}", action))
}

fn handle_debug(args: &[&str]) -> Result<SlashCommandOutput, String> {
    let target = args.first().copied().unwrap_or("[file:line]");
    let prompt = format!(
        "Set up debugging for vulnerability at `{}`:\n\
         1. Use `deploy_breakpoint` to generate .vscode/launch.json with breakpoints at sink lines\n\
         2. Configure DAP to attach to the target process (Docker container or local binary)\n\
         3. The breakpoint will pause execution at the vulnerable sink function\n\
         4. Inspect variables to confirm taint flow from user input to dangerous sink\n\
         Show the generated launch.json configuration.",
        target
    );
    output(prompt, &format!("Debug: {}", target))
}

fn handle_help() -> Result<SlashCommandOutput, String> {
    let text = "\
**Bellatrix India — /bellatrix commands**

`scan [path]`       SAST + taint analysis no arquivo/diretório
`campaign <url>`    Campanha AppSec completa (recon→exploit→report)
`report`            Gera relatório HackerOne de todos os findings
`intel <query>`     Busca semântica: CVEs, ATT&CK, APT, LOLBAS, OWASP
`status`            Status e progresso da campanha ativa
`docker <action>`   Gerencia Docker stack (up/down/logs/health)
`debug <file:line>` Configura DAP breakpoint no sink vulnerável

**MCP Tools no assistant:**
analyze_ast · trace_taint · search_threat_intel · generate_attack_graph
craft_evasive_payload · generate_poc · simulate_lateral_movement · deploy_breakpoint";

    output(text.to_string(), "Bellatrix Help")
}
