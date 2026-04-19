# Especificação de Módulos — Bellatrix India

> **Versão:** 2.0 | **Status:** Ativo | **Revisão:** 2026-04-19
>
> Este documento é a **fonte de verdade** para responsabilidades de cada crate.
> Toda nova função deve ser adicionada ao crate correto definido aqui.

---

## Mapa de Dependências

```
bin/orchestrator ──► agents ──► llm_router
bin/cli          ──► campaign   application ──► core_domain
                     report     intel
                     mcp_server infrastructure ──► core_domain
                     sast_engine
                     sca_engine
                     attack_graph
                     malware_crafter
```

**Regra:** dependências só fluem para a direita/baixo. Nenhum crate de `crates/` importa de `bin/`.

---

## `crates/core_domain`

**Responsabilidade:** Entidades de domínio, value objects e enums. Zero dependências externas além de `serde` e `uuid`. Nunca contém lógica de negócio.

### Módulos

| Módulo | Conteúdo |
|---|---|
| `models/finding.rs` | `Finding`, `Severity`, `Evidence`, `HttpEvidence` |
| `models/campaign.rs` | `Campaign`, `CampaignScope`, `CampaignState`, `ServiceType` |
| `models/target.rs` | `Target`, `Platform`, `TechStack` |
| `models/payload.rs` | `PayloadSpec`, `PayloadArtifact` |
| `models/taint.rs` | `TaintTrace`, `SourceNode`, `SinkNode`, `HopNode` |
| `models/llm.rs` | `CompletionRequest`, `CompletionResponse`, `CostTier` |
| `errors.rs` | `DomainError` (thiserror) |

### Constraints
- Sem I/O, sem async, sem dependências de infraestrutura
- Todos os types derivam `Debug`, `Clone`, `Serialize`, `Deserialize`
- Types com UUID derivam `PartialEq`, `Eq`, `Hash`

---

## `crates/application`

**Responsabilidade:** Ports (traits) que definem contratos entre domínio e infraestrutura. Contém casos de uso orquestrando múltiplos ports.

### Ports

| Trait | Propósito |
|---|---|
| `LlmProvider` | Interface para qualquer provedor LLM |
| `VectorStore` | Interface para Qdrant / qualquer vector DB |
| `CampaignStore` | Interface para persistência de campanhas (SQLite) |
| `LanguageAnalyzer` | Interface para parsers AST (tree-sitter) |
| `McpTool` | Interface para tools MCP individuais |
| `AttackGraphBuilder` | Interface para construção de grafos |
| `EvasionTechnique` | Interface para técnicas de evasão de malware |
| `PayloadEngine` | Interface para motores de geração de payload |
| `ReconTool` | Interface para tools de reconhecimento |
| `VulnScanner` | Interface para scanners de vulnerabilidade |
| `BinaryAnalyzer` | Interface para análise de binários |

### Use Cases

| Use Case | Descrição |
|---|---|
| `StartCampaign` | Inicializa campanha com validação de scope e autorização |
| `RunReconPhase` | Executa fase de reconhecimento usando ReconTools |
| `RunSastScan` | Orquestra scan SAST em path de código |
| `RunVulnScan` | Orquestra scan DAST em alvo web |
| `GenerateReport` | Agrega findings e gera relatório final |

### Constraints
- Traits usam `#[automock]` (mockall) para facilitar TDD
- Traits assíncronos usam `#[async_trait]`
- Nenhuma implementação concreta neste crate

---

## `crates/infrastructure`

**Responsabilidade:** Implementações concretas dos ports de `application`. Toda integração com sistemas externos vive aqui.

### Adaptadores

| Módulo | Implementa | Sistema externo |
|---|---|---|
| `qdrant/client.rs` | `VectorStore` | Qdrant via HTTP |
| `sqlite/campaign_repo.rs` | `CampaignStore` | SQLite via sqlx |
| `llm/openai_compat.rs` | `LlmProvider` | Qualquer API compatível OpenAI |
| `llm/anthropic.rs` | `LlmProvider` | Anthropic API nativa |
| `llm/ollama.rs` | `LlmProvider` | Ollama local |
| `mcp/http_client.rs` | `McpTool` | Tool containers via HTTP JSON-RPC |
| `parsers/treesitter.rs` | `LanguageAnalyzer` | tree-sitter grammars |

### Constraints
- Nunca contém lógica de negócio
- Toda configuração via structs de config injetadas (nunca env vars diretos)
- Erros retornam `InfraError` (thiserror), convertidos para `anyhow` na borda

---

## `crates/llm_router`

**Responsabilidade:** Abstração provider-agnostic para LLMs. Roteamento baseado em complexidade de tarefa. Retry logic, circuit breaker, rate limiting.

### Módulos

| Módulo | Conteúdo |
|---|---|
| `router.rs` | `LlmRouter` — dispatcha para provider correto |
| `classifier.rs` | `ComplexityClassifier` — classifica tarefa em Simple/Complex/Reasoning |
| `registry.rs` | `ProviderRegistry` — registro dinâmico de providers |
| `retry.rs` | Retry com exponential backoff |
| `circuit_breaker.rs` | Circuit breaker por provider |
| `providers/openai_compat.rs` | Adaptador OpenAI-compatible (DeepSeek, etc.) |
| `providers/anthropic.rs` | Adaptador Anthropic nativo |
| `providers/ollama.rs` | Adaptador Ollama local |

### Roteamento

```rust
pub enum TaskComplexity {
    Simple,    // geração de código, parsing, lookup → provider barato/rápido
    Complex,   // planejamento multi-step, análise profunda → provider premium
    Reasoning, // chain-of-thought longo, dedução → provider com reasoning nativo
    Permissive, // conteúdo ofensivo direto → provider com menos restrições
}
```

### Constraints
- O router nunca conhece qual provider específico está usando em cada slot
- Configuração de slots (Simple/Complex/Reasoning/Permissive) via arquivo TOML
- Nenhuma API key hardcoded

---

## `crates/agents`

**Responsabilidade:** Implementação dos agentes LLM com ciclo ReAct, auto-spawn de micro-agentes, personas de serviço.

### Módulos

| Módulo | Descrição |
|---|---|
| `factory.rs` | `AgentFactory` — instancia agentes por `TaskSpec` |
| `micro_agent.rs` | `MicroAgent` — implementação do ciclo ReAct |
| `planner.rs` | `PlannerAgent` — decompõe objetivo em `TaskSpec[]` |
| `memory.rs` | `MemoryAgent` — interface com Qdrant e SQLite |
| `appsec/agent.rs` | `AppSecAgent` — persona AppSec com tools permitidas |
| `pentest/agent.rs` | `PentestAgent` — persona Pentest com tools permitidas |
| `malware/agent.rs` | `MalwareEngineerAgent` — persona Malware Dev |
| `task_spec.rs` | `TaskSpec`, `TaskType`, `ToolAllowlist` |

### Ciclo ReAct

```
Iteration {
    thought: String,        // raciocínio do LLM
    action: ToolCall,       // tool a invocar
    observation: String,    // output da tool
    memory_update: Vec<Fact>, // fatos extraídos
}
```

### Tool Allowlist por persona

| Persona | Tools permitidas |
|---|---|
| `AppSecAgent` | semgrep, nuclei, httpx, caido, ffuf, subfinder, amass, sqlmap, grype |
| `PentestAgent` | todas as AppSec + metasploit, radare2, tor, mullvad |
| `MalwareEngineerAgent` | malware_crafter interno + radare2 + ferramentas de compilação |

### Constraints
- MicroAgents são efêmeros — criados para uma task, destruídos ao final
- Máximo de iterações configurável por TaskType (default: 10)
- Timeout por task configurável (default: 5 min)
- Nunca executa tools ofensivas sem `Campaign.authorized == true`

---

## `crates/sast_engine`

**Responsabilidade:** Análise estática via Semgrep subprocess + custom rules + taint tracking interno.

### Módulos

| Módulo | Conteúdo |
|---|---|
| `orchestrator.rs` | `SastOrchestrator` — roteia por linguagem para analyzer correto |
| `semgrep.rs` | `SemgrepRunner` — subprocess Semgrep com ruleset selecionável |
| `taint.rs` | `TaintTracker` — rastreio de fluxo tainted source → sink |
| `rules.rs` | `RuleSelector` — seleciona ruleset por linguagem e categoria |
| `parsers/php.rs` | `PhpAnalyzer` — implementa `LanguageAnalyzer` |
| `parsers/python.rs` | `PythonAnalyzer` |
| `parsers/javascript.rs` | `JavaScriptAnalyzer` |
| `parsers/rust.rs` | `RustAnalyzer` |
| `parsers/go.rs` | `GoAnalyzer` |
| `parsers/java.rs` | `JavaAnalyzer` |
| `parsers/csharp.rs` | `CSharpAnalyzer` |

### Rulesets Semgrep

```
rules/semgrep/
├── injection/          # SQLi, CommandI, SSTI, XXE, SSRF
├── auth/               # auth bypass, JWT, OAuth
├── crypto/             # weak crypto, hardcoded keys
├── deserialization/    # unsafe deserialize patterns
├── memory/             # buffer overflow (C/C++, unsafe Rust)
├── business_logic/     # mass assignment, race conditions
└── supply_chain/       # dependency confusion, typosquatting
```

---

## `crates/sca_engine`

**Responsabilidade:** Software Composition Analysis — encontra vulnerabilidades em dependências.

### Módulos

| Módulo | Conteúdo |
|---|---|
| `scanner.rs` | `ScaScanner` — orquestra Grype/Syft via MCP |
| `advisory.rs` | `AdvisoryDatabase` — cache local de advisories |
| `manifest.rs` | `ManifestParser` — parseia package.json, Cargo.toml, requirements.txt, pom.xml, go.mod |
| `osv_client.rs` | Cliente OSV.dev para lookup de vulnerabilidades |

---

## `crates/attack_graph`

**Responsabilidade:** Construção e análise de grafos de ataque usando petgraph.

### Módulos

| Módulo | Conteúdo |
|---|---|
| `graph.rs` | `AttackGraph` — grafo dirigido de findings com petgraph |
| `chain.rs` | `ChainAnalyzer` — encontra caminhos de ataque de maior impacto |
| `serializer.rs` | Exporta para JSON (Cytoscape.js) e Mermaid |
| `mitre_mapper.rs` | Mapeia findings para técnicas ATT&CK |

---

## `crates/malware_crafter`

**Responsabilidade:** Motor de geração de artefatos ofensivos para engajamentos RedTeam autorizados.

### Módulos

| Módulo | Conteúdo |
|---|---|
| `engine.rs` | `MalwareCraftingEngine` — pipeline principal |
| `mutation.rs` | `MutationEngine` — templates + variação de hashes |
| `evasion/amsi.rs` | `AmsiPatch` — bypass AMSI em-memória |
| `evasion/etw.rs` | `EtwBlocker` — bloqueio ETW |
| `evasion/xor.rs` | `XorEncoder` — encoding XOR rolling key |
| `evasion/sleep.rs` | `SleepObfuscation` — sleep masking anti-sandbox |
| `evasion/syscall.rs` | `DirectSyscall` — syscalls diretos (evita hooks NTDLL) |
| `evasion/unhook.rs` | `UnhookNtdll` — restaura NTDLL do disco |
| `stager/windows.rs` | Templates PE (shellcode, hollow, injection) |
| `stager/linux.rs` | Templates ELF (stager, persistence, LKM stub) |
| `compiler.rs` | `CompilerBridge` — invoca mingw-w64, rustc-cross via subprocess |

### Constraints
- Módulo só executa com `Campaign.authorized == true` e `ServiceType::MalwareDev`
- Compilação sempre isolada em container Docker dedicado
- Artefatos produzidos nunca transmitidos para fora do workspace do cliente

---

## `crates/mcp_server`

**Responsabilidade:** Gateway MCP — registra, roteia e audita chamadas a tool containers.

### Módulos

| Módulo | Conteúdo |
|---|---|
| `router.rs` | `McpRouter` — dispatch por nome de tool |
| `registry.rs` | `ToolRegistry` — auto-descoberta de containers |
| `health.rs` | `HealthChecker` — verifica containers a cada 30s |
| `audit.rs` | `AuditLog` — grava toda tool call com params e resultado |
| `tools/` | Definições de schema JSON para cada tool (8 core + extensível) |

---

## `crates/campaign`

**Responsabilidade:** Gestão de estado de campanha — criação, progresso, memória, histórico.

### Módulos

| Módulo | Conteúdo |
|---|---|
| `manager.rs` | `CampaignManager` — CRUD de campanhas |
| `state.rs` | `CampaignState` — FSM de estados de campanha |
| `memory.rs` | `CampaignMemory` — interface com Qdrant e SQLite |
| `scope.rs` | `ScopeValidator` — valida targets contra scope definido |
| `dedup.rs` | `FindingDeduplicator` — evita findings duplicados |

---

## `crates/intel`

**Responsabilidade:** Interface com RAG (Qdrant) — queries semânticas de inteligência de ameaças.

### Módulos

| Módulo | Conteúdo |
|---|---|
| `client.rs` | `IntelClient` — queries ao Qdrant |
| `embedder.rs` | `TextEmbedder` — gera embeddings via LLM provider |
| `query.rs` | `IntelQuery` — queries tipadas por collection |
| `schema.rs` | Schemas das collections Qdrant |

---

## `crates/report`

**Responsabilidade:** Geração de relatórios no formato HackerOne e exportações auxiliares.

### Módulos

| Módulo | Conteúdo |
|---|---|
| `hackerone.rs` | `HackerOneFormatter` — gera markdown HackerOne-compliant |
| `cvss.rs` | `CvssCalculator` — calcula CVSS 3.1 a partir de findings |
| `poc.rs` | `PocGenerator` — gera scripts PoC reproduzíveis |
| `timeline.rs` | `TimelineBuilder` — constrói timeline de descoberta |
| `templates/` | Templates Tera para cada tipo de vulnerability |

---

## `bin/orchestrator`

**Responsabilidade:** Daemon principal. Expõe interface STDIO MCP para VSCodium e API HTTP interna.

### Responsabilidades
- Inicializa stack (conecta Qdrant, SQLite, tool containers)
- Aceita campanhas via stdin (MCP) ou HTTP
- Gerencia lifecycle de campanhas e agentes
- Expõe endpoint de saúde e status

---

## `bin/cli`

**Responsabilidade:** Interface de linha de comando headless para automação CI/CD e uso direto.

### Subcomandos

| Comando | Descrição |
|---|---|
| `campaign start` | Inicia nova campanha com scope definido |
| `campaign status` | Status de campanha ativa |
| `scan sast` | Scan SAST em path local |
| `scan web` | Scan DAST em URL |
| `report generate` | Gera relatório de campanha concluída |
| `intel query` | Query direta ao RAG |
| `tools list` | Lista tools disponíveis e status |
| `tools health` | Verifica saúde dos containers |

---

## `tests/`

**Responsabilidade:** Testes de integração cross-crate que verificam o pipeline completo.

### Suites

| Arquivo | O que testa |
|---|---|
| `campaign_lifecycle.rs` | Criação → execução → report completo |
| `sast_pipeline.rs` | Semgrep → taint → findings |
| `mcp_dispatch.rs` | Router MCP com containers mock |
| `attack_graph_pipeline.rs` | Findings → grafo → chain analysis |
| `report_generation.rs` | Findings → HackerOne markdown |
| `llm_routing.rs` | Classifier → correto provider |
