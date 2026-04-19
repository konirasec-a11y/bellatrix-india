# Bellatrix India — Contexto do Projeto para Claude Code

## O que é este projeto

Plataforma ofensiva autônoma em Rust para equipes de RedTeam e Bug Bounty. Três módulos de serviço: **AppSec** (bug bounty), **Pentest** (web + desktop Windows/Linux), **Malware Dev** (serviço RedTeam). Toda a infraestrutura roda em Docker; VMs alvo em KVM/QEMU.

## Documentação obrigatória antes de trabalhar

- `implementation_plan.md` — arquitetura completa e roadmap
- `docs/ARCHITECTURE.md` — diagramas e fluxos de dados
- `docs/MODULES.md` — responsabilidades de cada crate
- `docs/SECURITY.md` — limites legais e política de uso

## Stack

- **Linguagem:** Rust (edição 2021, tokio async, workspace cargo)
- **LLM:** provider-agnostic via trait `LlmProvider` em `crates/llm_router`
- **Infra:** Docker Compose; nenhum binário instalado no host além de Docker e KVM
- **RAG:** Qdrant local (sem telemetria externa)
- **State:** SQLite via sqlx
- **SAST:** Semgrep OSS via subprocess
- **Scanner:** Nuclei via MCP container
- **Proxy:** Caido via MCP container

## Convenções de código

### Estrutura de crates

Cada crate tem responsabilidade única definida em `docs/MODULES.md`. Nunca adicionar lógica de negócio em `infrastructure/`. Nunca importar crates de `bin/` em `crates/`.

### TDD obrigatório

Todo código de produção começa com testes que falham. Ordem invariável:
1. Escrever teste que falha (Red)
2. Implementar mínimo para passar (Green)
3. Refatorar sem quebrar (Refactor)

Use `mockall` para todos os traits externos. Use `rstest` para testes parametrizados.

### Traits sobre structs concretas

Toda integração externa (LLM, Qdrant, SQLite, tools) é acessada via trait. Implementações concretas ficam em `crates/infrastructure/`.

### Erros

Use `thiserror` para erros de domínio. Use `anyhow` apenas em `bin/`. Nunca `.unwrap()` em código de produção — use `?` ou trate explicitamente.

### Async

Tokio como runtime. Todos os traits de I/O são `async_trait`. Sem `std::thread::sleep` — use `tokio::time::sleep`.

### Logging

Use `tracing` com spans contextuais. Nunca `println!` em código de produção. Nível padrão: `INFO`. Debug de campanha: `DEBUG`.

## Limites do agente

- Nunca commit direto em `main`
- Nunca remover testes existentes
- Nunca hard-code credenciais, endpoints ou chaves de API
- Nunca criar arquivos fora da estrutura definida em `implementation_plan.md` sem justificativa
- Todo novo crate deve ter entrada em `docs/MODULES.md`

## Comandos úteis

```bash
# Build completo
cargo build --workspace

# Todos os testes
cargo test --workspace

# Testes de um crate específico
cargo test -p llm_router

# Lint
cargo clippy --workspace -- -D warnings

# Docker stack
docker compose -f docker/compose.yml up -d

# Verificar containers
docker compose -f docker/compose.yml ps
```

## Contexto de segurança

Este projeto é para uso exclusivo em engajamentos autorizados. Ver `docs/SECURITY.md` para política completa. Código de exploração só é gerado quando `CampaignContext.authorized` é `true` e `scope` está definido.
