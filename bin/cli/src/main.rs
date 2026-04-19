use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bellatrix", about = "AI-powered offensive security platform CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file for vulnerabilities using Hybrid SAST
    Scan {
        #[arg(short, long)]
        file: String,
    },
    /// Craft an evasive payload via MCP tool
    Craft {
        #[arg(long, default_value = "windows")]
        os: String,
        #[arg(long, default_value = "x64")]
        arch: String,
        #[arg(long)]
        bypass_amsi: bool,
        #[arg(long)]
        bypass_etw: bool,
        #[arg(long)]
        encoder: Option<String>,
    },
    /// List all registered MCP tools
    ListTools,
    /// Run SCA against a dependency manifest (JSON array of {name, version})
    Sca {
        #[arg(short, long)]
        manifest: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("bellatrix=debug".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { file } => cmd_scan(&file).await?,
        Commands::Craft { os, arch, bypass_amsi, bypass_etw, encoder } => {
            cmd_craft(&os, &arch, bypass_amsi, bypass_etw, encoder).await?
        }
        Commands::ListTools => cmd_list_tools(),
        Commands::Sca { manifest } => cmd_sca(&manifest)?,
    }

    Ok(())
}

async fn cmd_scan(file: &str) -> Result<()> {
    use sast_engine::SastOrchestrator;

    let content = std::fs::read_to_string(file)?;
    let orchestrator = SastOrchestrator::new(vec![]);
    let findings = orchestrator.run_scan(file, &content).await?;

    if findings.is_empty() {
        println!("No findings for {file}");
    } else {
        for f in &findings {
            println!(
                "[{:?}] {} — {}:{}",
                f.severity, f.title, f.file_path, f.line_number
            );
        }
    }
    Ok(())
}

async fn cmd_craft(
    os: &str,
    arch: &str,
    bypass_amsi: bool,
    bypass_etw: bool,
    encoder: Option<String>,
) -> Result<()> {
    use application::PayloadEngine;
    use core_domain::PayloadSpec;
    use malware_crafter::MalwareCraftingEngine;

    let spec = PayloadSpec {
        os: os.to_string(),
        architecture: arch.to_string(),
        bypass_amsi,
        bypass_etw,
        encoder,
        bad_chars: vec![0x00],
    };

    let engine = MalwareCraftingEngine::from_spec(&spec);
    let payload = engine.generate_stager(&spec).await?;
    let hex: String = payload.iter().map(|b| format!("{:02x}", b)).collect();

    println!("Payload ({} bytes): {}", payload.len(), hex);
    Ok(())
}

fn cmd_list_tools() {
    let router = mcp_server::router::build_default_router();
    for tool in router.list_tools() {
        println!("• {} — {}", tool["name"], tool["description"]);
    }
}

fn cmd_sca(manifest: &str) -> Result<()> {
    use sca_engine::{AdvisoryDatabase, ScaScanner};
    use sca_engine::scanner::Dependency;

    let content = std::fs::read_to_string(manifest)?;
    let raw: Vec<serde_json::Value> = serde_json::from_str(&content)?;
    let deps: Vec<Dependency> = raw
        .iter()
        .map(|v| Dependency {
            name: v["name"].as_str().unwrap_or("").to_string(),
            version: v["version"].as_str().unwrap_or("").to_string(),
        })
        .collect();

    let db = AdvisoryDatabase::with_defaults();
    let scanner = ScaScanner::new(db);
    let findings = scanner.scan(&deps);

    if findings.is_empty() {
        println!("No known vulnerabilities found.");
    } else {
        for f in &findings {
            println!("[{:?}] {}", f.severity, f.title);
        }
    }
    Ok(())
}
