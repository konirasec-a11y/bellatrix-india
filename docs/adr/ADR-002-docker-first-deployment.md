# ADR-002: Docker-First — Toda Infraestrutura em Container

**Status:** Aceito  
**Data:** 2026-04-19  
**Decisores:** equipe Bellatrix India

---

## Contexto

A plataforma integra mais de 12 ferramentas de segurança externas (Semgrep, Nuclei, Metasploit, Radare2, SQLMap, etc.), cada uma com suas próprias dependências, versões, e requisitos de sistema. Instalar todas no host criaria:
- Conflitos de dependências entre ferramentas
- Dificuldade em reproduzir o ambiente em diferentes máquinas
- Superfície de ataque expandida no host
- Impossibilidade de garantir versões específicas das ferramentas

---

## Decisão

**Toda** infraestrutura roda em Docker containers orquestrados por Docker Compose. As únicas dependências do host são:
1. Docker Engine + Compose plugin
2. KVM + libvirt + QEMU (para VMs alvo)
3. Rust toolchain (para build — pode ser movida para CI)

Cada ferramenta de segurança tem seu próprio container com um servidor MCP wrapper que expõe a ferramenta via JSON-RPC 2.0 HTTP. O `mcp_router` do orchestrator atua como gateway.

**Rede:**
- `bellatrix_net` (interna): comunicação entre containers sem acesso à internet
- `egress_net`: apenas containers que precisam de saída (tor, mullvad, ferramentas de recon)
- Tráfego ofensivo sempre via container `tor` ou `mullvad`

---

## Consequências

**Positivas:**
- Ambiente 100% reproduzível
- Isolamento de ferramentas — um crash em sqlmap não afeta o orchestrator
- Fácil upgrade: `docker pull` + restart
- Superfície de ataque mínima no host
- Tráfego de ataque não expõe IP real do host

**Negativas:**
- Overhead de startup (~30s para stack completa)
- Complexidade de networking (resolver DNS entre containers)
- Docker socket precisa de proteção adicional

**Mitigação:**
- Health checks garantem containers prontos antes de usar
- DNS interno Docker resolve nomes por service name automaticamente
- Docker socket exposto apenas ao container orchestrator com volume read-only
