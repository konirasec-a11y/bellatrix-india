# Política de Segurança e Uso Autorizado — Bellatrix India

> **Versão:** 2.0 | **Status:** Ativo | **Revisão:** 2026-04-19  
> **Classificação:** Internal / Confidential

---

## 1. Declaração de Uso Autorizado

Bellatrix India é uma ferramenta de segurança ofensiva desenvolvida **exclusivamente** para:

1. **Engajamentos de pentest autorizados** — com contrato assinado, scope definido, e Rules of Engagement (RoE) acordadas com o cliente
2. **Bug bounty em programas ativos** — em alvos dentro do scope publicado pelo programa (HackerOne, Bugcrowd, Intigriti, etc.)
3. **Pesquisa de vulnerabilidades em OSS** — em software sob licença OSS, para reporte responsável ao mantenedor e à MITRE
4. **Desenvolvimento de capacidades RedTeam** — dentro de ambiente de laboratório controlado (VMs locais) para clientes com contrato de serviço
5. **Testes em infraestrutura própria** — em sistemas que o operador possui ou tem autorização explícita por escrito

**O uso desta plataforma contra sistemas sem autorização explícita é ilegal e viola os Termos de Uso.**

---

## 2. Controles Técnicos Obrigatórios

### 2.1 Campo `Campaign.authorized`

```rust
// crates/core_domain/src/models/campaign.rs
pub struct Campaign {
    pub authorized: bool,  // DEVE ser true para execução ofensiva
    pub authorization_ref: Option<String>, // ref do contrato ou programa de BB
    // ...
}
```

O sistema **recusa executar** as seguintes operações quando `authorized == false`:
- Chamadas ao container `metasploit`
- Chamadas ao container `sqlmap` com modo `--level >= 2`
- Chamadas ao `MalwareCraftingEngine` com `ServiceType::MalwareDev`
- Qualquer tool com categoria `Exploitation` no registro MCP

### 2.2 Validação de Scope

```rust
// crates/campaign/src/scope.rs
pub struct ScopeValidator;

impl ScopeValidator {
    /// Retorna Err se o target está fora do scope definido na campanha
    pub fn validate_target(&self, target: &Target, scope: &CampaignScope) -> anyhow::Result<()>;

    /// Verifica se IP/domínio pertence ao scope antes de qualquer ação ofensiva
    pub fn is_in_scope(&self, target: &str, scope: &CampaignScope) -> bool;
}
```

Toda invocação de tool ofensiva passa pelo `ScopeValidator`. Se o target não está no scope, a operação é recusada e registrada no audit log.

### 2.3 Audit Log Imutável

Todo step de campanha é gravado no SQLite com:
- Timestamp UTC
- Tool invocada
- Parâmetros completos
- Output resumido
- Resultado (`success` / `failure` / `out_of_scope`)
- Hash SHA-256 do registro anterior (cadeia de integridade)

O audit log **não pode ser deletado** via interface normal — apenas via acesso direto ao arquivo SQLite.

---

## 3. Programa de Bug Bounty

### 3.1 Verificação de scope

Antes de iniciar uma campanha de bug bounty, o operador deve:

1. Verificar o scope atual no programa (HackerOne, Bugcrowd, etc.)
2. Definir `CampaignScope.targets` apenas com domínios/IPs **dentro** do scope
3. Adicionar a `CampaignScope.excluded` qualquer exclusão listada no programa
4. Definir `Campaign.authorization_ref` com o URL do programa e data de consulta

### 3.2 Limites de testes

| Tipo de teste | Permitido em BB | Observação |
|---|---|---|
| Recon passivo | Sempre | Nunca excede rate limits |
| Scan de vulnerabilidades | Sim | Respeitar rate limiting do alvo |
| Exploração | Apenas para PoC mínimo | Nunca persistência real |
| Exfiltração de dados reais | **Nunca** | Mesmo com acesso, não exfiltrar dados de usuários |
| DoS/DDoS | **Nunca** | Excluído de qualquer engajamento |
| Engenharia social | **Nunca** via plataforma | Fora do escopo da ferramenta |
| Ataques a usuários reais | **Nunca** | Apenas infra do programa |

### 3.3 Disclosure responsável

Para CVEs em OSS descobertos via plataforma:
1. Reportar ao mantenedor via canal de segurança do projeto (90 dias de embargo)
2. Reportar à MITRE via https://cveform.mitre.org/ após concordância com mantenedor
3. Publicar advisory apenas após patch disponível ou término do embargo
4. Registrar na campanha com `Finding.disclosure_status` = `Reported | Patched | Published`

---

## 4. Módulo Malware Dev — Controles Adicionais

### 4.1 Pré-requisitos

O módulo `MalwareDev` só pode ser ativado quando:
- `Campaign.service_type == ServiceType::MalwareDev`
- `Campaign.authorized == true`
- `Campaign.authorization_ref` contém referência ao contrato do cliente
- `Campaign.scope.targets` lista **apenas** ambientes do cliente (VMs, lab interno)

### 4.2 Isolamento de artefatos

- Artefatos produzidos são armazenados **apenas** no volume `workspace` do Docker
- Artefatos nunca são transmitidos fora da rede `bellatrix_net` automaticamente
- Transferência ao cliente é responsabilidade manual do operador via canal seguro
- Artefatos são deletados do workspace ao encerrar a campanha (`campaign close`)

### 4.3 Ambiente de teste

Todos os testes de funcionalidade de malware devem ser realizados **exclusivamente** nas VMs KVM locais. Nunca em:
- Sistemas produtivos do cliente
- Cloud pública sem autorização escrita
- Qualquer sistema fora do scope da campanha

---

## 5. Gestão de Credenciais

### 5.1 API keys de LLM

- Armazenadas exclusivamente como Docker secrets
- Nunca em variáveis de ambiente, arquivos `.env` commitados, ou logs
- Rotacionadas a cada 90 dias ou imediatamente após comprometimento suspeito
- Nunca compartilhadas entre operadores — cada um usa suas próprias keys

### 5.2 Credenciais de alvos

- Credenciais descobertas durante testes nunca são armazenadas em texto plano
- Registradas apenas como evidência (hash ou referência ao screenshot)
- Destruídas ao final da campanha se não há necessidade de evidência para relatório

### 5.3 Acesso ao host

```bash
# Permissões mínimas recomendadas para o usuário operador
# O daemon não roda como root
sudo usermod -aG docker,libvirt $OPERATOR_USER

# Docker socket com grupo específico
sudo chown root:docker /var/run/docker.sock
sudo chmod 660 /var/run/docker.sock
```

---

## 6. Retenção de Dados

| Dado | Retenção | Destruição |
|---|---|---|
| Findings de campanha | Duração do contrato + 1 ano | `campaign purge --id <id>` |
| Audit log | 2 anos (compliance) | Acesso direto SQLite necessário |
| Artefatos de malware | Durante campanha ativa | `campaign close` deleta automaticamente |
| Screenshots e evidências | Duração do contrato | `campaign purge --id <id>` |
| Dados RAG (intel) | Indefinido — dados públicos | Não contém dados de clientes |
| Credenciais de API | Até rotação | `docker secret rm` |

---

## 7. Resposta a Incidentes

### 7.1 Acesso não autorizado à plataforma

```bash
# Imediatamente:
docker compose -f docker/compose.yml down
virsh destroy windows-target-01
virsh destroy linux-target-01

# Revogar API keys
# Notificar clientes ativos
# Preservar logs para análise forense
```

### 7.2 Fuga de scope acidental

1. Parar campanha imediatamente: `./bin/bellatrix campaign pause --id <id>`
2. Verificar audit log para entender o que foi acessado
3. Notificar o proprietário do sistema afetado
4. Documentar incidente para relatório interno
5. Revisar validação de scope para prevenir recorrência

### 7.3 Comprometimento de artefato de malware

1. Revogar qualquer C2 ativo associado ao artefato
2. Notificar o cliente imediatamente
3. Cooperar com investigação forense se necessário
4. Deletar todas as cópias do artefato

---

## 8. Framework Legal de Referência

| Jurisdição | Lei relevante | Observação |
|---|---|---|
| Brasil | Lei 12.737/2012 (Carolina Dieckmann) | Acesso não autorizado é crime |
| Brasil | Marco Civil da Internet (Lei 12.965/2014) | Responsabilidade por uso de dados |
| EUA | Computer Fraud and Abuse Act (CFAA) | Para alvos/clientes americanos |
| UE | Diretiva NIS2 / GDPR | Para alvos europeus |
| Internacional | Budapeste Convention on Cybercrime | Framework multilateral |

**Regra geral:** tenha sempre autorização **escrita e específica** antes de qualquer teste. Autorização verbal não é suficiente.

---

## 9. Contato

Para reportar uso indevido desta plataforma ou dúvidas sobre escopo de autorização, contatar o responsável técnico do projeto antes de prosseguir com qualquer ação.
