# Bellatrix India — Implementation Plan (v2.0)

> **Classificação:** Internal / Confidential  
> **Versão:** 2.0 — Arquitetura Real  
> **Status:** Active  

---

## 1. Visão Geral do Sistema

Bellatrix India é uma **plataforma ofensiva autônoma** de nível de produção para equipes de RedTeam e Bug Bounty. Ela orquestra agentes de IA, ferramentas de segurança e inteligência de ameaças em três módulos de serviço independentes, mas que compartilham infraestrutura comum.

### 1.1 Serviços

| Serviço | Descrição | Público-alvo |
|---|---|---|
| **AppSec** | SAST + DAST + SCA automatizados com ciclo ReAct, foco em bug bounty competitivo | AppSec engineers, bug bounty hunters |
| **Pentest** | Campanhas ofensivas completas: recon → exploit → pós-exploração (Web + Windows/Linux Desktop) | Pentesters, RedTeam operators |
| **Malware Dev** | Desenvolvimento de artefatos ofensivos e evasão para engajamentos RedTeam | RedTeam operators, clientes de serviço |

### 1.2 Princípios Não-Negociáveis

1. **Provider-agnostic LLM** — nenhuma dependência hard-coded em um provedor específico
2. **Docker-first** — toda a infraestrutura roda em container; nenhum binário instalado no host além do Docker engine e KVM
3. **TDD mandatório** — todo código de produção tem testes antes da implementação
4. **Memória de campanha** — o sistema nunca repete o mesmo teste em uma sessão; toda observação é persistida
5. **Outputs auditáveis** — cada decisão do agente registra sua cadeia de raciocínio e evidências

---

## 2. Arquitetura de Alto Nível

```
┌──────────────────────────────────────────────────────────────────┐
│                        HOST (Parrot/Kali)                         │
│                                                                    │
│   ┌─────────────────────────────────────────────────────────┐    │
│   │                  DOCKER COMPOSE NETWORK                  │    │
│   │                                                           │    │
│   │  ┌──────────────┐   ┌──────────────┐  ┌─────────────┐  │    │
│   │  │  orchestrator │   │  mcp_router  │  │   qdrant    │  │    │
│   │  │  (Rust daemon)│   │  (Rust server│  │ (vector DB) │  │    │
│   │  └──────┬───────┘   └──────┬───────┘  └─────────────┘  │    │
│   │         │                  │                              │    │
│   │         ▼                  ▼                              │    │
│   │  ┌─────────────────────────────────────────────────┐    │    │
│   │  │              TOOL CONTAINERS (MCPs)              │    │    │
│   │  │  caido │ semgrep │ nuclei │ radare2 │ metasploit │    │    │
│   │  │  sqlmap│ ffuf    │ amass  │ httpx   │ grype      │    │    │
│   │  │  tor   │ mullvad │ proxychains │ subfinder      │    │    │
│   │  └─────────────────────────────────────────────────┘    │    │
│   │                                                           │    │
│   └─────────────────────────────────────────────────────────┘    │
│                                                                    │
│   ┌─────────────────────────────────┐                            │
│   │  KVM / libvirt / QEMU           │                            │
│   │  ├── Windows 10/11 target VM    │                            │
│   │  └── Linux target VM            │                            │
│   └─────────────────────────────────┘                            │
└──────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   LLM PROVIDERS   │
                    │  (external APIs)  │
                    │  ├── Provider A   │
                    │  └── Provider B   │
                    └───────────────────┘
```

---

## 3. Estrutura de Crates (Monorepo Cargo)

```
bellatrix-india/
├── Cargo.toml                    # workspace root
├── CLAUDE.md                     # contexto do projeto para Claude Code
├── implementation_plan.md        # este arquivo
├── docs/                         # documentação técnica
│   ├── ARCHITECTURE.md
│   ├── MODULES.md
│   ├── DEPLOYMENT.md
│   ├── RAG_STRATEGY.md
│   ├── SECURITY.md
│   ├── REPORTING.md
│   └── adr/                      # Architecture Decision Records
├── crates/
│   ├── core_domain/              # entidades, value objects, erros de domínio
│   ├── application/              # ports (traits), use cases, interfaces
│   ├── infrastructure/           # adaptadores externos (Qdrant, SQLite, HTTP)
│   ├── llm_router/               # abstração provider-agnostic + complexity router
│   ├── agents/                   # agentes: AppSec, Pentest, Malware, micro-agents
│   ├── sast_engine/              # Semgrep subprocess + custom rules + taint tracking
│   ├── sca_engine/               # Grype/OSV/NVD SCA
│   ├── attack_graph/             # grafos de ataque via petgraph
│   ├── malware_crafter/          # payload engine + evasion pipeline
│   ├── mcp_server/               # roteador MCP + registro de tools
│   ├── campaign/                 # estado de campanha, memória, histórico
│   ├── report/                   # formatador HackerOne + CVSS calculator
│   └── intel/                    # cliente RAG Qdrant + feed ingesters
├── bin/
│   ├── orchestrator/             # daemon principal (gRPC + MCP STDIO)
│   └── cli/                      # CLI headless para automação
├── extension/                    # Extensão Zed (Rust/WASM) — pacote independente
│   ├── Cargo.toml                # target: wasm32-wasi (não entra no workspace nativo)
│   ├── extension.toml            # manifesto Zed (id, context_servers, slash_commands)
│   └── src/
│       ├── lib.rs                # entry point — implementa zed::Extension
│       ├── context_server.rs     # configura vsc_backend como MCP context server
│       ├── slash_commands.rs     # /bellatrix scan|campaign|report|intel
│       └── diagnostics.rs        # Finding → LSP Diagnostic (overlay no editor)
├── docker/
│   ├── compose.yml               # stack completa
│   ├── orchestrator/Dockerfile
│   └── tools/                    # Dockerfiles das tool containers
├── rules/
│   ├── semgrep/                  # regras Semgrep customizadas por categoria
│   └── nuclei/                   # templates Nuclei customizados
├── scripts/
│   ├── setup-kvm.sh              # provisionamento de VMs alvo
│   └── ingest-rag.sh             # pipeline de ingestão RAG
└── tests/                        # testes de integração cross-crate
```

---

## 4. Camada LLM — Provider-Agnostic

### 4.1 Trait Central

```rust
// crates/llm_router/src/provider.rs
#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn name(&self) -> &str;
    fn supports_reasoning(&self) -> bool;
    fn cost_tier(&self) -> CostTier; // Cheap | Standard | Premium
    async fn complete(&self, req: CompletionRequest) -> anyhow::Result<CompletionResponse>;
    async fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>>;
}
```

### 4.2 Complexity Router

```
Tarefa recebida
     │
     ▼
┌────────────────────────────────────────────┐
│          ComplexityClassifier              │
│  • token count estimado                    │
│  • número de steps esperados               │
│  • requer raciocínio multi-hop?            │
│  • envolve código ofensivo direto?         │
└──────────────┬─────────────────┬───────────┘
               │                 │
        SIMPLE/FAST         COMPLEX/REASONING
               │                 │
               ▼                 ▼
      Provider A (cheap)   Provider B (premium)
      ex: DeepSeek-chat    ex: Claude Sonnet
      ex: Llama3-local     ex: DeepSeek-R1
```

### 4.3 Providers Suportados (Day 1)

| Provider ID | Implementa | Uso |
|---|---|---|
| `deepseek_chat` | `LlmProvider` | Tarefas simples, código ofensivo |
| `deepseek_reasoner` | `LlmProvider` | Raciocínio complexo |
| `anthropic_claude` | `LlmProvider` | Planejamento de campanha, relatórios |
| `openai_gpt` | `LlmProvider` | Fallback genérico |
| `ollama_local` | `LlmProvider` | Offline / air-gapped |

Qualquer provedor compatível com OpenAI Chat Completions API pode ser adicionado implementando o trait.

---

## 5. Sistema de Agentes — Auto-Spawn

### 5.1 Hierarquia

```
CampaignOrchestrator (singleton por campanha)
    │
    ├── PlannerAgent (Claude/Reasoner) — decompõe objetivo em tasks
    │
    ├── MicroAgent (ephemeral, 1 por task)
    │   ├── ReconAgent
    │   ├── SastAgent
    │   ├── FuzzAgent
    │   ├── ExploitAgent
    │   ├── BinaryAnalysisAgent
    │   └── ReportAgent
    │
    └── MemoryAgent (singleton) — grava/consulta estado no Qdrant + SQLite
```

### 5.2 Ciclo ReAct (Reason → Act → Observe)

```
┌─────────────────────────────────────────┐
│             MicroAgent Loop             │
│                                         │
│  1. REASON  — LLM planeja próximo step  │
│  2. ACT     — invoca MCP tool           │
│  3. OBSERVE — processa output da tool   │
│  4. UPDATE  — atualiza memória local    │
│  5. DECIDE  — continua ou retorna result│
│                                         │
│  Max iterations: configurável por task  │
│  Timeout: configurável por task         │
└─────────────────────────────────────────┘
```

### 5.3 Spawn dinâmico

O `PlannerAgent` emite um `TaskSpec` para cada sub-tarefa. O `AgentFactory` instancia o `MicroAgent` correto com:
- Tools permitidas (allowlist por tipo de tarefa)
- Provider LLM (baseado em complexidade)
- Timeout e max_iterations
- Contexto de campanha (alvo, scope, findings já coletados)

---

## 6. Tool Containers (MCPs via Docker)

### 6.1 Mapa de Tools

| Container | Ferramenta | Categoria | MCP Name |
|---|---|---|---|
| `caido` | Caido proxy | Web Intercept | `web_proxy` |
| `semgrep` | Semgrep OSS | SAST | `sast_scan` |
| `nuclei` | Nuclei | DAST/Scanner | `vuln_scan` |
| `radare2` | Radare2 | Reversão | `binary_analysis` |
| `metasploit` | Metasploit Framework | Exploitation | `exploit_framework` |
| `sqlmap` | SQLMap | SQLi | `sqli_test` |
| `ffuf` | FFuF | Fuzzing | `web_fuzz` |
| `amass` | Amass | Recon | `subdomain_enum` |
| `subfinder` | Subfinder | Recon | `subfinder` |
| `httpx` | httpx | Recon/Probe | `http_probe` |
| `grype` | Grype + Syft | SCA | `sca_scan` |
| `tor` | Tor + ProxyChains | Anonimização | `anon_proxy` |
| `mullvad` | Mullvad CLI | VPN | `vpn_control` |

### 6.2 Protocolo MCP

Todos os containers expõem um servidor JSON-RPC 2.0 via HTTP (porta interna). O `mcp_server` no orchestrator atua como gateway, roteando calls pelo nome do tool. Containers que não têm servidor HTTP próprio recebem um sidecar MCP wrapper em Python/Go.

### 6.3 Segurança entre containers

- Network isolada: `bellatrix_net` (bridge interna)
- Nenhum container com acesso à internet exceto `tor` e `mullvad`
- Tráfego ofensivo sempre roteado via `tor` ou `mullvad`
- Secrets via Docker secrets, nunca em variáveis de ambiente plain

---

## 7. Inteligência de Ameaças (RAG)

### 7.1 Collections Qdrant

| Collection | Fonte | Conteúdo |
|---|---|---|
| `cve_intel` | NVD/OSV | CVEs indexados por CWE, CPE, CVSS, vetor |
| `attack_ttp` | MITRE ATT&CK STIX | Técnicas/sub-técnicas/procedimentos |
| `apt_playbooks` | MITRE Groups, Open CTI | TTPs de grupos APT específicos |
| `lolbas_lolol` | LOLBAS.github.io | Binários nativos Windows/Linux para evasão |
| `owasp_patterns` | OWASP WSTG, Top 10 | Padrões de vulnerabilidade web |
| `ptes_phases` | PTES standard | Metodologia de pentest por fase |
| `oss_vuln_patterns` | CVEs históricos OSS | Padrões de código vulnerável para hunting |
| `semgrep_rules` | Semgrep Registry + custom | Regras ofensivas indexadas por categoria |

### 7.2 Uso em Campanha

```
1. Recon identifica stack: "Rails 7.0 + PostgreSQL + Redis"
2. RAG query: "vulnerabilidades Rails 7.0 com CVSS >= 7"
3. RAG query: "TTPs ATT&CK para aplicações web Ruby"
4. RAG query: "regras Semgrep para injection em Ruby"
5. PlannerAgent recebe contexto → gera hipóteses de ataque
```

---

## 8. Módulos de Serviço

### 8.1 AppSec / Bug Bounty

**Objetivo:** Encontrar vulnerabilidades em escopo definido e gerar relatório HackerOne válido e detalhado.

**Pipeline:**
```
Scope Input (URL / domínio / repo)
    │
    ▼
[Recon] subfinder + httpx + amass
    │
    ▼
[Tech Fingerprint] whatweb + nuclei tech-detect
    │
    ▼
[SAST] Semgrep (se código disponível) com regras customizadas
    │
    ▼
[SCA] Grype/Syft em manifests expostos ou código
    │
    ▼
[DAST] Caido intercept + Nuclei templates + FFuF
    │
    ▼
[Hypothesis → Exploit] PlannerAgent + MicroAgents por hipótese
    │
    ▼
[Validation] PoC com request/response real registrado
    │
    ▼
[Report] HackerOne format + CVSS + timeline + evidências
```

**Alvos primários:**
- Injection: SQLi, SSTI, XXE, Command Injection
- Auth: IDOR, Broken Auth, JWT issues, OAuth misconfig
- Business Logic: Mass Assignment, Race Conditions, BFLA/BOLA
- Infra: SSRF, Path Traversal, Deserialization, Dependency CVEs

### 8.2 Pentest

**Objetivo:** Executar campanha ofensiva completa com relatório técnico e executivo.

**Plataformas:**
- **Web:** mesmo pipeline do AppSec com exploração ativa
- **Windows Desktop (via KVM):** análise PE, privesc LOLBAS, credential harvesting, lateral movement
- **Linux Desktop (via KVM):** SUID/SGID, sudo misconfig, cron abuse, kernel CVEs

**Fases PTES:**
1. Pre-engagement (scope, rules of engagement)
2. Intelligence Gathering (passivo + ativo)
3. Threat Modeling (ATT&CK mapping)
4. Vulnerability Analysis
5. Exploitation
6. Post-Exploitation
7. Reporting

### 8.3 Malware Dev (RedTeam Service)

**Objetivo:** Produzir artefatos ofensivos customizados para engajamentos RedTeam autorizados.

**Capacidades:**
- Windows: PE shellcode, process hollowing, DLL injection, AMSI/ETW bypass
- Linux: ELF, persistence (systemd/cron), rootkit básico (LKM)
- C2: stager gerado para frameworks open source (Havoc, Sliver, Mythic)
- Evasion pipeline: XOR/RC4, sleep masking, unhook NTDLL, syscalls diretos
- Mutation: variação de hashes por compilação com templates dinâmicos

**LLM primário:** Provider configurado como `permissive` na rota de complexidade (ex: DeepSeek Chat).

---

## 9. Extensão Zed (Editor Integration)

### 9.1 Por que Zed

- Extensões escritas em **Rust compilado para WASM** — consistência total com o stack do projeto
- Suporte nativo a **MCP Context Servers** — o `vsc_backend` é registrado diretamente como context server sem adaptadores
- Assistant panel integrado — o operador conversa com os agentes dentro do editor
- Debugger nativo via DAP — breakpoints automáticos nos sinks descobertos
- Performance superior a VSCode para edição de arquivos grandes (binários, logs)

### 9.2 Integração MCP (Context Server)

```
Zed Editor
    │
    ├── Assistant Panel ──► Context Server: vsc_backend (MCP STDIO)
    │                            │
    │                            └──► Todos os 8 MCP tools disponíveis
    │                                 para o AI assistant dentro do Zed
    │
    ├── Slash Commands
    │   ├── /bellatrix scan [file]     → SAST inline
    │   ├── /bellatrix campaign [url]  → inicia campanha AppSec
    │   ├── /bellatrix report          → gera relatório HackerOne
    │   └── /bellatrix intel [query]   → query ao RAG
    │
    ├── Diagnostics (LSP overlay)
    │   └── Findings aparecem como erros/warnings nas linhas do código
    │       com severity color coding (Critical=vermelho, High=laranja...)
    │
    └── Breakpoints automáticos
        └── Finding.sink_line → DAP breakpoint na linha do sink
```

### 9.3 Arquitetura da extensão

```
extension/                    (pacote WASM independente)
├── extension.toml            manifesto Zed
├── Cargo.toml                [lib] crate-type = ["cdylib"]
└── src/
    ├── lib.rs                impl zed::Extension — entry point
    ├── context_server.rs     lança vsc_backend via docker exec
    ├── slash_commands.rs     handlers de /bellatrix *
    └── diagnostics.rs        Finding JSON → lsp_types::Diagnostic
```

### 9.4 Compatibilidade com outros editores

| Editor | Suporte | Método |
|---|---|---|
| **Zed** | **Primário** | Extensão Rust/WASM nativa + MCP Context Server |
| VSCode / VSCodium | Secundário | `vsc_backend` como MCP server via `mcp` config em settings.json |
| Neovim | Comunidade | Plugin Lua consumindo MCP via `mcphub.nvim` |
| JetBrains | Futuro | Plugin Kotlin (não planejado neste ciclo) |

Para VSCode/VSCodium, nenhuma extensão custom é necessária — basta adicionar ao `settings.json`:
```json
{
  "mcp.servers": {
    "bellatrix": {
      "command": "docker",
      "args": ["compose", "-f", "docker/compose.yml", "exec", "-T", "orchestrator", "/app/vsc_backend"]
    }
  }
}
```

---

## 10. Relatório HackerOne

### 9.1 Campos obrigatórios gerados automaticamente

- `title` — máximo 200 chars, descritivo
- `severity` — Critical / High / Medium / Low (mapeado do CVSS)
- `cvss_vector` — CVSS 3.1 string calculada pelo sistema
- `vulnerability_information` — markdown com: descrição técnica, root cause, impacto
- `steps_to_reproduce` — sequência numerada com requests/responses reais
- `proof_of_concept` — script Python/curl funcional e reproduzível
- `impact` — análise de impacto no negócio
- `remediation` — recomendação técnica específica
- `timeline` — timestamps de descoberta, teste, validação

### 9.2 Mapeamentos automáticos

```
CVSS >= 9.0 → Critical
CVSS 7.0–8.9 → High
CVSS 4.0–6.9 → Medium
CVSS < 4.0 → Low
```

---

## 10. Infraestrutura KVM para Targets

### 10.1 Windows Target VM

- Base: Windows 10/11 LTSC (ISO local)
- Provisionamento: scripts Ansible via libvirt API
- Snapshot pré-ataque: restaurável entre campanhas
- Acesso: RDP + WinRM para automação
- Agente de validação: PowerShell listener para confirmar exploração

### 10.2 Linux Target VM

- Base: Ubuntu 22.04 / Debian 12 (ISO local)
- Provisionamento: cloud-init
- Snapshot pré-ataque: restaurável entre campanhas
- Acesso: SSH
- Configurações vulneráveis: pré-configuradas por cenário de pentest

---

## 11. Roadmap de Implementação

### Fase 1 — Infraestrutura Base (Semana 1-2)
- [ ] Docker Compose completo com todos os tool containers
- [ ] `crates/infrastructure`: Qdrant client, SQLite campaign store
- [ ] `crates/llm_router`: trait + complexity router + 2 providers (DeepSeek + Anthropic)
- [ ] `crates/intel`: Qdrant query interface + feed schema
- [ ] MCP wrappers para: semgrep, nuclei, httpx, subfinder
- [ ] TDD de todos os adapters com mocks de containers

### Fase 2 — Agentes e Orquestração (Semana 3-4)
- [ ] `crates/agents`: PlannerAgent + AgentFactory + ReAct loop
- [ ] `crates/campaign`: CampaignState + MemoryAgent
- [ ] `bin/orchestrator`: daemon com gRPC + MCP STDIO
- [ ] Pipeline completo AppSec (recon → report) em staging
- [ ] TDD do ciclo de spawn de micro-agents

### Fase 3 — Tools Avançadas (Semana 5-6)
- [ ] MCP wrappers para: caido, sqlmap, ffuf, radare2
- [ ] `crates/sast_engine`: integração real Semgrep subprocess
- [ ] `crates/sca_engine`: integração real Grype/Syft
- [ ] Attack graph com dados reais de campanha
- [ ] Scripts de ingestão RAG (NVD, ATT&CK, LOLBAS)

### Fase 4 — Pentest e Malware Dev (Semana 7-9)
- [ ] KVM provisioning scripts (Windows + Linux)
- [ ] Módulo Pentest completo com fases PTES
- [ ] `crates/malware_crafter`: compiladores reais (mingw, rustc cross)
- [ ] Evasion pipeline com testes contra VMs locais
- [ ] C2 stager integration (Havoc/Sliver via MCP)

### Fase 5 — Report e Hardening (Semana 10)
- [ ] `crates/report`: HackerOne formatter com CVSS 3.1
- [ ] `bin/cli`: interface headless completa
- [ ] Testes end-to-end em targets reais autorizados
- [ ] Auditoria de segurança da plataforma
- [ ] Documentação final e release

---

## 12. Stack de Tecnologias

| Camada | Tecnologia | Justificativa |
|---|---|---|
| Runtime | Rust (tokio async) | Performance, segurança de memória, binários estáticos |
| Containerização | Docker + Compose | Isolamento, reprodutibilidade |
| VM | KVM + libvirt + QEMU | Virtualização nativa Linux, API programável |
| Vector DB | Qdrant | RAG local, sem telemetria externa |
| State DB | SQLite (via sqlx) | Zero-dependency, embedded |
| Grafo | petgraph | Análise de caminhos de ataque |
| Parser | tree-sitter | AST multilinguagem sem compilador externo |
| SAST | Semgrep OSS | Melhor cobertura regras de segurança |
| Scanner | Nuclei | Melhor ecossistema de templates |
| Proxy | Caido | OSS, scriptável, API moderna |
| RE | Radare2 | OSS, scriptável (r2pipe), multiplataforma |
| Exploitation | Metasploit | Maior base de exploits |
| Reporting | Rust + Markdown | Full control, nenhum serviço externo |
