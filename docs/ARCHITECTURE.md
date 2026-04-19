# Arquitetura do Sistema — Bellatrix India

> **Versão:** 2.0 | **Status:** Ativo | **Revisão:** 2026-04-19

---

## 1. Visão de Contexto (C4 Level 1)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         ATORES EXTERNOS                                   │
│                                                                            │
│  [Operador RedTeam]   [Bug Bounty Hunter]   [AppSec Engineer]            │
│         │                     │                      │                    │
│         └─────────────────────┴──────────────────────┘                   │
│                               │                                            │
│                   ┌───────────▼───────────┐                              │
│                   │    Bellatrix India     │                              │
│                   │  (plataforma ofensiva) │                              │
│                   └───────────┬───────────┘                              │
│                               │                                            │
│         ┌─────────────────────┼─────────────────────┐                   │
│         │                     │                      │                    │
│  [LLM Providers]      [Targets autorizados]   [Plataformas Report]      │
│  DeepSeek/Claude/     Web apps, APIs,          HackerOne, Bugcrowd,     │
│  OpenAI/Ollama        VMs KVM                  relatório interno        │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Visão de Containers (C4 Level 2)

```
┌─────────────────────────────────────────────── bellatrix_net ───────────────────────────────────────────────┐
│                                                                                                               │
│  ┌──────────────────────────┐    ┌──────────────────────────┐    ┌──────────────────────┐                   │
│  │      orchestrator        │    │       mcp_router         │    │       qdrant          │                   │
│  │  (Rust async daemon)     │◄──►│  (Rust MCP gateway)      │    │  (vector DB :6333)    │                   │
│  │                          │    │                          │    │                       │                   │
│  │  • CampaignOrchestrator  │    │  • Tool registry         │    │  • cve_intel          │                   │
│  │  • PlannerAgent (LLM)    │    │  • JSON-RPC dispatch     │    │  • attack_ttp         │                   │
│  │  • AgentFactory          │    │  • Auth / rate limit     │    │  • apt_playbooks      │                   │
│  │  • MemoryAgent           │    │  • Tool health check     │    │  • lolbas_lolol       │                   │
│  │  • LlmRouter             │    │                          │    │  • owasp_patterns     │                   │
│  │  • ReportEngine          │    └──────────┬───────────────┘    │  • oss_vuln_patterns  │                   │
│  └──────────────┬───────────┘               │                    └──────────────────────┘                   │
│                 │                           │                                                                │
│                 │         ┌─────────────────▼───────────────────────────────────────────────┐              │
│                 │         │                    TOOL CONTAINERS (MCP servers)                  │              │
│                 │         │                                                                   │              │
│                 │         │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │              │
│                 │         │  │  caido   │ │ semgrep  │ │  nuclei  │ │ radare2  │           │              │
│                 │         │  │ :8080    │ │ :8081    │ │ :8082    │ │ :8083    │           │              │
│                 │         │  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │              │
│                 │         │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │              │
│                 │         │  │metasploit│ │  sqlmap  │ │   ffuf   │ │  amass   │           │              │
│                 │         │  │ :8084    │ │ :8085    │ │ :8086    │ │ :8087    │           │              │
│                 │         │  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │              │
│                 │         │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │              │
│                 │         │  │subfinder │ │  httpx   │ │  grype   │ │   tor    │           │              │
│                 │         │  │ :8088    │ │ :8089    │ │ :8090    │ │ :8091    │           │              │
│                 │         │  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │              │
│                 │         └─────────────────────────────────────────────────────────────────┘              │
│                 │                                                                                            │
│  ┌──────────────▼───────────┐                                                                              │
│  │       sqlite_state        │                                                                              │
│  │  (campanha, findings,     │                                                                              │
│  │   histórico de steps)     │                                                                              │
│  └──────────────────────────┘                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

                         │ KVM Bridge (virbr0)
                         ▼
         ┌───────────────────────────────────┐
         │         KVM / libvirt             │
         │  ┌─────────────────────────────┐  │
         │  │   windows-target-01 VM      │  │
         │  │   (Windows 10/11 LTSC)      │  │
         │  └─────────────────────────────┘  │
         │  ┌─────────────────────────────┐  │
         │  │   linux-target-01 VM        │  │
         │  │   (Ubuntu 22.04 / Debian)   │  │
         │  └─────────────────────────────┘  │
         └───────────────────────────────────┘

                         │ HTTPS (saída)
                         ▼
            ┌─────────────────────────┐
            │      LLM Providers      │
            │  (API externa via HTTPS)│
            └─────────────────────────┘
```

---

## 3. Visão de Componentes (C4 Level 3) — Orchestrator

```
┌──────────────────────────────────── orchestrator ────────────────────────────────────┐
│                                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│  │                          CampaignOrchestrator                                    │ │
│  │                                                                                   │ │
│  │  ┌─────────────────┐   ┌─────────────────┐   ┌──────────────────────────────┐  │ │
│  │  │  PlannerAgent   │   │  AgentFactory   │   │       MemoryAgent            │  │ │
│  │  │                 │   │                 │   │                              │  │ │
│  │  │  • decompõe     │   │  • instancia    │   │  • query Qdrant (semântico)  │  │ │
│  │  │    objetivo em  │   │    MicroAgents  │   │  • query SQLite (estruturado)│  │ │
│  │  │    TaskSpec[]   │   │  • aplica       │   │  • grava findings            │  │ │
│  │  │  • usa LLM      │   │    allowlist de │   │  • grava steps executados    │  │ │
│  │  │    reasoner     │   │    tools por    │   │  • detecta duplicatas        │  │ │
│  │  │  • consulta RAG │   │    tipo de task │   │                              │  │ │
│  │  └────────┬────────┘   └────────┬────────┘   └──────────────────────────────┘  │ │
│  │           │                     │                                                 │ │
│  └───────────┼─────────────────────┼─────────────────────────────────────────────┘ │
│              │                     │                                                  │
│              ▼                     ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────────┐   │
│  │                           MicroAgent (ReAct Loop)                             │   │
│  │                                                                               │   │
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐  │   │
│  │  │ REASON   │──►│   ACT    │──►│ OBSERVE  │──►│  UPDATE  │──►│  DECIDE  │  │   │
│  │  │ LLM plan │   │ MCP call │   │ parse    │   │ memory   │   │ continue │  │   │
│  │  │ next step│   │ tool exec│   │ output   │   │ update   │   │ or return│  │   │
│  │  └──────────┘   └──────────┘   └──────────┘   └──────────┘   └────┬─────┘  │   │
│  │       ▲                                                              │        │   │
│  │       └──────────────────── loop ────────────────────────────────────┘        │   │
│  └───────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                        │
│  ┌───────────────────────────────────────────────────────────────────────────────┐   │
│  │                           LlmRouter                                           │   │
│  │                                                                               │   │
│  │  ┌───────────────────────┐         ┌─────────────────────────────────────┐  │   │
│  │  │  ComplexityClassifier │         │         Provider Registry            │  │   │
│  │  │                       │         │                                       │  │   │
│  │  │  • tokens estimados   │──────►  │  SIMPLE  → provider_a (cheap/fast)  │  │   │
│  │  │  • steps esperados    │         │  COMPLEX → provider_b (reasoning)   │  │   │
│  │  │  • reasoning required │         │  OFFLINE → ollama_local             │  │   │
│  │  └───────────────────────┘         └─────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                        │
│  ┌───────────────────────────────────────────────────────────────────────────────┐   │
│  │                           ReportEngine                                        │   │
│  │                                                                               │   │
│  │  • Agrega findings de campanha                                               │   │
│  │  • Calcula CVSS 3.1 para cada finding                                        │   │
│  │  • Deduplica e prioriza por severity                                         │   │
│  │  • Gera markdown HackerOne format                                            │   │
│  │  • Gera script PoC autônomo por finding                                      │   │
│  └───────────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Fluxo de Dados — Campanha AppSec

```
Operador define scope
        │
        ▼
CampaignOrchestrator.start(scope)
        │
        ├─► MemoryAgent.check_existing() → carrega estado anterior se existe
        │
        ▼
PlannerAgent.plan(scope, rag_context)
        │  [LLM reasoner + RAG query]
        │  Retorna: Vec<TaskSpec>
        │
        ▼ (para cada TaskSpec em paralelo)
AgentFactory.spawn(task_spec)
        │
        ▼
MicroAgent::run(task_spec)
        │
        ├─ REASON: "quero fazer subdomain enum do alvo X"
        ├─ ACT:    mcp_router.call("subfinder", {domain: "target.com"})
        ├─ OBSERVE: ["api.target.com", "admin.target.com", ...]
        ├─ UPDATE:  memory.store_subdomains([...])
        ├─ REASON: "tenho 15 subdomains, próximo: probe HTTP"
        ├─ ACT:    mcp_router.call("httpx", {targets: [...]})
        ├─ OBSERVE: [{url, status, tech, title}, ...]
        ├─ UPDATE:  memory.store_http_targets([...])
        └─ RETURN: ObservationResult

        ▼ (convergência de todos os MicroAgents)
PlannerAgent.re-plan(observations)
        │  [gera novas TaskSpecs baseado em findings]
        │
        ▼
... (ciclo continua até scope esgotado ou timeout)
        │
        ▼
ReportEngine.generate(campaign_state)
        │
        ▼
HackerOne report (markdown)
```

---

## 5. Protocolo MCP (Tool Interface)

### 5.1 Request

```json
{
  "jsonrpc": "2.0",
  "id": "uuid-v4",
  "method": "tools/call",
  "params": {
    "name": "sast_scan",
    "arguments": {
      "file_path": "/workspace/target/app.py",
      "language": "python",
      "ruleset": ["injection", "deserialization", "auth"]
    }
  }
}
```

### 5.2 Response

```json
{
  "jsonrpc": "2.0",
  "id": "uuid-v4",
  "result": {
    "findings": [
      {
        "rule_id": "python.django.security.injection.tainted-sql-string",
        "severity": "ERROR",
        "message": "SQL injection via tainted user input",
        "path": "/workspace/target/app.py",
        "start": {"line": 42, "col": 8},
        "end": {"line": 42, "col": 45},
        "fix": "Use parameterized queries"
      }
    ],
    "scanned_files": 1,
    "rules_applied": 847
  }
}
```

### 5.3 Health Check

Cada container responde a `GET /health` com status HTTP 200 quando pronto. O `mcp_router` verifica saúde de todos os containers na inicialização e a cada 30s.

---

## 6. Modelo de Dados — Domínio

```
Campaign
├── id: Uuid
├── name: String
├── scope: CampaignScope
│   ├── targets: Vec<Target>
│   ├── excluded: Vec<String>
│   └── service: ServiceType (AppSec | Pentest | MalwareDev)
├── authorized: bool        ← OBRIGATÓRIO true para execução
├── started_at: DateTime
├── state: CampaignState (Planning | Active | Paused | Completed)
└── findings: Vec<Finding>

Finding
├── id: Uuid
├── campaign_id: Uuid
├── title: String
├── severity: Severity (Critical|High|Medium|Low|Info)
├── cvss_vector: Option<String>
├── cvss_score: Option<f32>
├── cwe: Vec<String>
├── target: Target
├── evidence: Evidence
│   ├── request: Option<HttpEvidence>
│   ├── response: Option<HttpEvidence>
│   ├── screenshot: Option<PathBuf>
│   └── binary_artifact: Option<PathBuf>
├── reproduction_steps: Vec<String>
├── poc_script: Option<String>
├── remediation: String
└── discovered_at: DateTime

Target
├── url: Option<Url>
├── ip: Option<IpAddr>
├── hostname: Option<String>
├── platform: Platform (Web | Windows | Linux)
└── tech_stack: Vec<String>
```

---

## 7. Decisões de Segurança da Arquitetura

### 7.1 Isolamento de rede
- Tráfego ofensivo **nunca** sai direto do host
- Rota obrigatória: `orchestrator → tor/mullvad container → target`
- Qdrant e SQLite nunca expostos fora da `bellatrix_net`

### 7.2 Autorização de campanha
- `Campaign.authorized` deve ser `true` explicitamente
- Sistema recusa executar tools ofensivas se `authorized == false`
- Scope definido e verificado antes de qualquer ação

### 7.3 Rastreabilidade
- Todo step de MicroAgent é gravado com timestamp, tool, params, output
- LLM reasoning chain é persistido para auditoria
- Logs nunca contêm dados do alvo em texto plano (referenciados por ID)

### 7.4 Credenciais
- API keys de LLM: Docker secrets (nunca env vars)
- Chaves de acesso a alvos: geradas por campanha, rotacionadas ao final
- Nenhum dado de cliente persiste além da campanha ativa
