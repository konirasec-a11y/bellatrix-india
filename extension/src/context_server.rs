use zed_extension_api::{self as zed, settings::ContextServerSettings};

pub const SERVER_ID: &str = "bellatrix";

/// Constrói o comando para iniciar o vsc_backend como MCP STDIO server.
///
/// Estratégia de localização (em ordem):
/// 1. Docker Compose disponível no projeto → `docker compose exec orchestrator vsc_backend`
/// 2. Binário local configurado nas settings → caminho explícito
/// 3. Binário `vsc_backend` no PATH do sistema
pub fn server_command(
    project: &zed::Project,
    settings: &ContextServerSettings,
) -> zed::Result<zed::Command> {
    let config = settings
        .settings
        .as_ref()
        .and_then(|v| serde_json::from_value::<BellatrixConfig>(v.clone()).ok())
        .unwrap_or_default();

    // Procura compose.yml no worktree raiz do projeto
    if let Some(compose_path) = find_compose_file(project) {
        return Ok(zed::Command {
            command: "docker".to_string(),
            args: vec![
                "compose".to_string(),
                "-f".to_string(),
                compose_path,
                "exec".to_string(),
                "-T".to_string(),           // sem TTY (STDIO puro)
                "orchestrator".to_string(),
                "/app/vsc_backend".to_string(),
            ],
            env: build_env(&config),
        });
    }

    // Fallback: binário local
    let binary = config
        .binary_path
        .clone()
        .unwrap_or_else(|| "vsc_backend".to_string());

    Ok(zed::Command {
        command: binary,
        args: vec![],
        env: build_env(&config),
    })
}

fn find_compose_file(project: &zed::Project) -> Option<String> {
    let worktrees = project.worktrees();
    let root = worktrees.first()?.root_path();
    let candidates = [
        "docker/compose.yml",
        "docker-compose.yml",
        "compose.yml",
    ];
    for candidate in &candidates {
        let path = format!("{}/{}", root, candidate);
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    None
}

fn build_env(config: &BellatrixConfig) -> Vec<(String, String)> {
    let mut env = vec![
        ("RUST_LOG".to_string(), config.log_level.clone()),
    ];
    if let Some(url) = &config.qdrant_url {
        env.push(("QDRANT_URL".to_string(), url.clone()));
    }
    env
}

/// Configuração da extensão lida do Zed settings.json do usuário.
///
/// Exemplo de configuração em ~/.config/zed/settings.json:
/// ```json
/// {
///   "context_servers": {
///     "bellatrix": {
///       "settings": {
///         "log_level": "debug",
///         "qdrant_url": "http://localhost:6333"
///       }
///     }
///   }
/// }
/// ```
#[derive(Debug, serde::Deserialize)]
#[serde(default)]
pub struct BellatrixConfig {
    pub binary_path: Option<String>,
    pub qdrant_url: Option<String>,
    pub log_level: String,
}

impl Default for BellatrixConfig {
    fn default() -> Self {
        Self {
            binary_path: None,
            qdrant_url: None,
            log_level: "info".to_string(),
        }
    }
}
