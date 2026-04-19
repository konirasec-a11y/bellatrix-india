mod context_server;
mod dap;
mod diagnostics;
mod slash_commands;
pub mod tasks;

use zed_extension_api::{self as zed, settings::ContextServerSettings};

/// Extensão Bellatrix India para Zed.
///
/// Pontos de integração:
/// - Context Server (MCP): vsc_backend disponível no assistant panel
/// - Slash Commands: /bellatrix scan|campaign|report|intel|status
/// - Language Server: diagnostics de findings como overlays LSP no editor
/// - DAP Debugger: attach a processos em containers Docker
/// - Tasks: gerenciamento do Docker Compose integrado ao task runner do Zed
struct BellatrixExtension;

impl zed::Extension for BellatrixExtension {
    fn new() -> Self {
        BellatrixExtension
    }

    /// Inicia o vsc_backend como MCP context server.
    ///
    /// Zed mantém este processo vivo durante a sessão. Todos os 8 MCP tools
    /// ficam disponíveis no assistant panel via protocolo MCP/JSON-RPC 2.0.
    fn context_server_command(
        &mut self,
        _context_server_id: &zed::ContextServerId,
        project: &zed::Project,
    ) -> zed::Result<zed::Command> {
        let settings =
            ContextServerSettings::for_project(context_server::SERVER_ID, project)?;
        context_server::server_command(project, &settings)
    }

    /// Handler dos slash commands /bellatrix no assistant panel.
    ///
    /// Injeta prompts estruturados que guiam o AI a usar os MCP tools
    /// corretos para cada operação de segurança.
    fn run_slash_command(
        &self,
        command: zed::SlashCommand,
        args: Vec<String>,
        worktree: Option<&zed::Worktree>,
    ) -> Result<zed::SlashCommandOutput, String> {
        slash_commands::run(command, args, worktree)
    }

    /// Retorna o comando para iniciar o language server de diagnostics.
    ///
    /// O Bellatrix LSP converte findings de campanha em diagnostics LSP
    /// (overlays coloridos nas linhas do editor) via textDocument/publishDiagnostics.
    fn language_server_command(
        &mut self,
        language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> zed::Result<zed::Command> {
        diagnostics::lsp_command(language_server_id, worktree)
    }
}

zed::register_extension!(BellatrixExtension);
