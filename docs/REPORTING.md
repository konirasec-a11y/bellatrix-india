# Especificação de Relatórios — HackerOne Format

> **Versão:** 2.0 | **Status:** Ativo | **Revisão:** 2026-04-19

---

## 1. Visão Geral

O `ReportEngine` gera relatórios de vulnerabilidade no formato aceito pela plataforma HackerOne. Cada `Finding` de campanha com evidência válida produz um relatório independente. O relatório é gerado em Markdown e pode ser submetido diretamente via HackerOne API ou copiado para o formulário web.

---

## 2. Mapeamento de Campos

### 2.1 Campos obrigatórios HackerOne → Finding

| Campo HackerOne | Campo interno | Gerado por |
|---|---|---|
| `title` | `Finding.title` | LLM (ReportAgent) |
| `severity` | `Finding.severity` | `CvssCalculator` |
| `vulnerability_information` | template renderizado | `HackerOneFormatter` |
| `impact` | `Finding.impact_analysis` | LLM (ReportAgent) |
| `steps_to_reproduce` | `Finding.reproduction_steps` | MicroAgent (validação) |
| `proof_of_concept` | `Finding.poc_script` | `PocGenerator` |

### 2.2 Campos calculados automaticamente

| Campo | Método de cálculo |
|---|---|
| CVSS score | `CvssCalculator::score_from_finding()` |
| CVSS vector | `CvssCalculator::vector_from_finding()` |
| CWE | Mapeado pelo Semgrep rule ou ATT&CK TTP |
| Timeline | Timestamps de cada step de MicroAgent |

---

## 3. Template de Relatório

```markdown
# [SEVERITY] [TITLE]

## Vulnerability Type
[CWE-XX: Nome do CWE] — [Categoria OWASP/ATT&CK se aplicável]

## CVSS Score
**[SCORE]/10.0** — [CVSS Vector String]
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

## Summary
[Parágrafo técnico conciso: o que é, onde está, por que é vulnerável]

## Target
- **URL/Host:** `[target]`
- **Endpoint:** `[endpoint afetado]`
- **Parâmetro vulnerável:** `[param]`
- **Tecnologia:** `[stack detectada]`

---

## Steps to Reproduce

1. [Passo 1 — configuração, se necessário]
2. [Passo 2 — request inicial]
3. [Passo 3 — payload/input malicioso]
4. [Passo 4 — observação do resultado vulnerável]
5. [Passo 5 — confirmação da vulnerabilidade]

### Request
```http
[MÉTODO] [PATH] HTTP/1.1
Host: [host]
Content-Type: [content-type]
[Headers relevantes]

[Body se aplicável]
```

### Response
```http
HTTP/1.1 [STATUS]
[Headers relevantes]

[Body mostrando evidência da vulnerabilidade]
```

---

## Proof of Concept

```python
#!/usr/bin/env python3
"""
PoC: [TÍTULO DA VULNERABILIDADE]
Target: [TARGET]
Discovered: [DATA]
Severity: [SEVERITY]
"""
import requests

TARGET = "[URL]"

def exploit():
    # [Comentário explicativo]
    payload = "[payload]"
    
    r = requests.get(TARGET, params={"[param]": payload})
    
    if "[indicador de sucesso]" in r.text:
        print(f"[VULN] Vulnerabilidade confirmada!")
        print(f"Response: {r.text[:500]}")
    else:
        print("[-] Não vulnerável ou payload bloqueado")

if __name__ == "__main__":
    exploit()
```

**Resultado esperado:**
[Descrição do output que confirma a vulnerabilidade]

---

## Impact

### Técnico
[Descrição técnica detalhada do impacto: o que um atacante pode fazer]

### Negócio
[Impacto para o negócio/usuários: privacidade, integridade, disponibilidade]

### Classificação
- **Confidencialidade:** [None/Low/High]
- **Integridade:** [None/Low/High]
- **Disponibilidade:** [None/Low/High]
- **Escopo:** [Changed/Unchanged]

---

## Remediation

### Recomendação imediata
[Fix específico para este caso: código, configuração, etc.]

### Código vulnerável
```[linguagem]
[trecho vulnerável]
```

### Código corrigido
```[linguagem]
[trecho corrigido]
```

### Referências
- [CWE link]
- [OWASP link]
- [Documentação do framework/linguagem]

---

## Timeline

| Data | Evento |
|---|---|
| [DATA] | Vulnerabilidade descoberta via [tool] |
| [DATA] | Exploração confirmada com PoC |
| [DATA] | Relatório gerado |
| [DATA] | Submetido ao programa |
```

---

## 4. Cálculo CVSS 3.1

### 4.1 Vetor base por tipo de vulnerabilidade

| CWE / Tipo | AV | AC | PR | UI | S | C | I | A | Score típico |
|---|---|---|---|---|---|---|---|---|---|
| RCE sem auth (CWE-78) | N | L | N | N | C | H | H | H | 9.8 |
| SQLi (CWE-89) | N | L | N | N | U | H | H | N | 9.1 |
| XSS Refletido (CWE-79) | N | L | N | R | U | L | N | N | 4.3 |
| XSS Stored (CWE-79) | N | L | L | N | C | L | L | N | 6.1 |
| SSRF (CWE-918) | N | L | N | N | C | H | N | N | 8.6 |
| IDOR (CWE-639) | N | L | L | N | U | H | N | N | 6.5 |
| Auth Bypass (CWE-287) | N | L | N | N | U | H | H | N | 9.1 |
| LFI/Path Traversal (CWE-22) | N | L | N | N | U | H | N | N | 7.5 |
| XXE (CWE-611) | N | L | N | N | U | H | H | N | 9.1 |

### 4.2 Ajustes contextuais

O `CvssCalculator` aplica ajustes baseados no contexto detectado:

- **PR (Privileges Required):** High se requer auth → Medium se auth fraca → None se público
- **UI (User Interaction):** Required para XSS refletido, None para stored/CSRF
- **S (Scope):** Changed se vulnerabilidade afeta outros componentes (ex: SSRF alcança serviços internos)
- **A (Availability):** High apenas se PoC demonstra impacto em disponibilidade

### 4.3 Mapeamento severity

```rust
// crates/report/src/cvss.rs
pub fn severity_from_score(score: f32) -> Severity {
    match score {
        s if s >= 9.0 => Severity::Critical,
        s if s >= 7.0 => Severity::High,
        s if s >= 4.0 => Severity::Medium,
        s if s > 0.0  => Severity::Low,
        _             => Severity::Informational,
    }
}
```

---

## 5. Geração de PoC

### 5.1 Tipos suportados

| Vulnerabilidade | Linguagem PoC | Método |
|---|---|---|
| SQLi | Python (requests) | Payload em param com detecção de diferença |
| XSS | Python (requests) | Reflexão de payload no response |
| SSRF | Python (requests) | Callback para servidor de escuta |
| Command Injection | Python (requests) | Output de comando no response |
| Path Traversal | Python (requests) | Conteúdo de /etc/passwd ou equivalente |
| IDOR | Python (requests) | Acesso a recurso de outro usuário |
| Auth Bypass | Python (requests) | Acesso a endpoint autenticado sem token |
| Buffer Overflow | Python (struct) | Crash reproduzível com input controlado |
| Binary RCE | Python (subprocess) | Payload binário com shell reverso |

### 5.2 Template Python base

```python
#!/usr/bin/env python3
"""
PoC autogenerated by Bellatrix India
CVE/Finding: {finding_id}
Target: {target}
Severity: {severity}
CVSS: {cvss_score} ({cvss_vector})
"""
import sys
import requests

requests.packages.urllib3.disable_warnings()

TARGET = "{target_url}"
TIMEOUT = 10

def check_vulnerable(response: requests.Response) -> bool:
    indicators = {success_indicators}
    return any(ind in response.text for ind in indicators)

def exploit():
    session = requests.Session()
    session.verify = False
    
    # Step 1: {step_description}
    r = session.{method}(
        f"{{TARGET}}{endpoint}",
        {params_or_data},
        headers={headers},
        timeout=TIMEOUT
    )
    
    if check_vulnerable(r):
        print(f"[CRITICAL] {vulnerability_name} confirmed on {{TARGET}}")
        print(f"[*] Status: {{r.status_code}}")
        print(f"[*] Evidence: {{r.text[:{evidence_slice}]}}")
        return True
    
    print("[-] Target not vulnerable or payload was blocked")
    return False

if __name__ == "__main__":
    success = exploit()
    sys.exit(0 if success else 1)
```

---

## 6. Validação de Relatório

Antes de submeter ao HackerOne, o `ReportEngine` valida:

```rust
// crates/report/src/hackerone.rs
pub struct ReportValidator;

impl ReportValidator {
    pub fn validate(&self, report: &HackerOneReport) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();
        
        // Título
        if report.title.len() > 200 {
            errors.push(ValidationError::TitleTooLong);
        }
        if report.title.len() < 10 {
            errors.push(ValidationError::TitleTooShort);
        }
        
        // Steps to reproduce
        if report.steps_to_reproduce.len() < 3 {
            errors.push(ValidationError::InsufficientSteps);
        }
        
        // Evidência obrigatória
        if report.evidence.is_empty() {
            errors.push(ValidationError::NoEvidence);
        }
        
        // CVSS
        if report.cvss_vector.is_none() {
            errors.push(ValidationError::MissingCvss);
        }
        
        // PoC
        if report.proof_of_concept.is_none() {
            errors.push(ValidationError::MissingPoc);
        }
        
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}
```

---

## 7. Relatório de Campanha (Multi-Finding)

Para campanhas com múltiplos findings, o `ReportEngine` gera um relatório executivo consolidado:

```markdown
# Relatório de Campanha — [NOME DO PROGRAMA]
**Data:** [DATA]  
**Scope testado:** [SCOPE]  
**Total de findings:** [N]

## Resumo Executivo

| Severity | Count | Findings |
|---|---|---|
| Critical | [N] | [títulos] |
| High | [N] | [títulos] |
| Medium | [N] | [títulos] |
| Low | [N] | [títulos] |

## Findings por Severidade

### Critical

[Finding 1 completo]
---
[Finding 2 completo]

### High
[...]

## Metodologia
[Ferramentas usadas, fases executadas, duração]

## Timeline
[Timeline consolidada da campanha]
```

---

## 8. Submissão via API HackerOne

```rust
// crates/report/src/hackerone_api.rs
pub struct HackerOneClient {
    api_token: String,
    program_handle: String,
}

impl HackerOneClient {
    pub async fn submit_report(&self, report: &HackerOneReport) -> anyhow::Result<String> {
        // Retorna o report_id após submissão bem-sucedida
        // POST https://api.hackerone.com/v1/reports
        todo!("implementar na Fase 5")
    }
}
```
