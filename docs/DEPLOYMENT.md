# Guia de Deployment — Bellatrix India

> **Versão:** 2.0 | **Status:** Ativo | **Revisão:** 2026-04-19

---

## 1. Pré-requisitos do Host

### 1.1 Sistema Operacional

| OS | Suporte | Observação |
|---|---|---|
| Parrot OS (Security) | **Primário** | Recomendado — ferramentas de segurança pré-instaladas |
| Kali Linux (rolling) | **Primário** | Alternativa equivalente |
| Ubuntu 22.04 LTS | Suportado | Requer instalação manual de deps |
| Debian 12 | Suportado | Requer instalação manual de deps |

### 1.2 Dependências do host (apenas estas)

```bash
# Docker Engine + Compose plugin
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# KVM + libvirt + QEMU (para VMs alvo)
sudo apt install -y \
  qemu-kvm \
  libvirt-daemon-system \
  libvirt-clients \
  bridge-utils \
  virtinst \
  virt-manager

# Rust toolchain (para build do orchestrator)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-pc-windows-gnu  # cross-compile Windows

# Verificar KVM
sudo modprobe kvm-intel  # ou kvm-amd
virsh list --all
```

### 1.3 Hardware mínimo

| Recurso | Mínimo | Recomendado |
|---|---|---|
| CPU | 8 cores | 16+ cores (VMs paralelas) |
| RAM | 32 GB | 64 GB |
| Armazenamento | 500 GB SSD | 1 TB NVMe |
| Rede | 100 Mbps | 1 Gbps |

---

## 2. Estrutura de Diretórios Docker

```
docker/
├── compose.yml                    # stack completa
├── compose.dev.yml                # overrides para desenvolvimento
├── .env.example                   # template de variáveis (sem valores reais)
├── secrets/                       # Docker secrets (git-ignored)
│   ├── llm_provider_a_key         # API key provider A
│   ├── llm_provider_b_key         # API key provider B
│   └── campaign_signing_key       # chave para assinar relatórios
├── orchestrator/
│   ├── Dockerfile
│   └── config/
│       ├── providers.toml         # configuração de providers LLM
│       └── tools.toml             # configuração de tools MCP
└── tools/
    ├── semgrep/
    │   ├── Dockerfile
    │   └── mcp_wrapper.py         # servidor MCP para Semgrep
    ├── nuclei/
    │   ├── Dockerfile
    │   └── mcp_wrapper.py
    ├── caido/
    │   └── Dockerfile
    ├── radare2/
    │   ├── Dockerfile
    │   └── mcp_wrapper.py
    ├── metasploit/
    │   ├── Dockerfile
    │   └── mcp_wrapper.py
    ├── sqlmap/
    │   ├── Dockerfile
    │   └── mcp_wrapper.py
    ├── ffuf/
    │   ├── Dockerfile
    │   └── mcp_wrapper.py
    ├── amass/
    │   ├── Dockerfile
    │   └── mcp_wrapper.py
    ├── subfinder/
    │   ├── Dockerfile
    │   └── mcp_wrapper.py
    ├── httpx/
    │   ├── Dockerfile
    │   └── mcp_wrapper.py
    ├── grype/
    │   ├── Dockerfile
    │   └── mcp_wrapper.py
    └── tor/
        └── Dockerfile
```

---

## 3. Docker Compose — Stack Completa

```yaml
# docker/compose.yml — esquema (valores reais em .env + secrets)

name: bellatrix

networks:
  bellatrix_net:
    driver: bridge
    internal: true   # sem acesso direto à internet
  egress_net:
    driver: bridge   # somente tor e mullvad saem aqui

volumes:
  qdrant_data:
  sqlite_data:
  workspace:         # compartilhado entre orchestrator e tools
  semgrep_rules:
  nuclei_templates:

secrets:
  llm_provider_a_key:
    file: ./secrets/llm_provider_a_key
  llm_provider_b_key:
    file: ./secrets/llm_provider_b_key

services:

  # ── Core ─────────────────────────────────────────────────────────

  orchestrator:
    build: ./orchestrator
    networks: [bellatrix_net]
    volumes:
      - workspace:/workspace
      - sqlite_data:/data/sqlite
      - ./orchestrator/config:/config:ro
    secrets: [llm_provider_a_key, llm_provider_b_key]
    depends_on: [qdrant, semgrep, nuclei, httpx, subfinder]
    restart: unless-stopped
    environment:
      - RUST_LOG=info,bellatrix=debug

  qdrant:
    image: qdrant/qdrant:latest
    networks: [bellatrix_net]
    volumes:
      - qdrant_data:/qdrant/storage
    ports:
      - "127.0.0.1:6333:6333"   # só host local
    restart: unless-stopped

  # ── Recon Tools ───────────────────────────────────────────────────

  subfinder:
    build: ./tools/subfinder
    networks: [bellatrix_net, egress_net]
    volumes: [workspace:/workspace]
    restart: unless-stopped

  httpx:
    build: ./tools/httpx
    networks: [bellatrix_net, egress_net]
    volumes: [workspace:/workspace]
    restart: unless-stopped

  amass:
    build: ./tools/amass
    networks: [bellatrix_net, egress_net]
    volumes: [workspace:/workspace]
    restart: unless-stopped

  # ── Analysis Tools ────────────────────────────────────────────────

  semgrep:
    build: ./tools/semgrep
    networks: [bellatrix_net]
    volumes:
      - workspace:/workspace
      - semgrep_rules:/rules:ro
    restart: unless-stopped

  nuclei:
    build: ./tools/nuclei
    networks: [bellatrix_net, egress_net]
    volumes:
      - workspace:/workspace
      - nuclei_templates:/templates
    restart: unless-stopped

  grype:
    build: ./tools/grype
    networks: [bellatrix_net]
    volumes: [workspace:/workspace]
    restart: unless-stopped

  # ── Exploitation Tools ─────────────────────────────────────────────

  caido:
    build: ./tools/caido
    networks: [bellatrix_net]
    volumes: [workspace:/workspace]
    restart: unless-stopped

  sqlmap:
    build: ./tools/sqlmap
    networks: [bellatrix_net]
    volumes: [workspace:/workspace]
    restart: unless-stopped

  ffuf:
    build: ./tools/ffuf
    networks: [bellatrix_net]
    volumes: [workspace:/workspace]
    restart: unless-stopped

  metasploit:
    build: ./tools/metasploit
    networks: [bellatrix_net]
    volumes: [workspace:/workspace]
    restart: unless-stopped

  radare2:
    build: ./tools/radare2
    networks: [bellatrix_net]
    volumes: [workspace:/workspace]
    restart: unless-stopped

  # ── Anonymization ─────────────────────────────────────────────────

  tor:
    build: ./tools/tor
    networks: [bellatrix_net, egress_net]
    restart: unless-stopped
    # SOCKS5 proxy: tor:9050 (interno à bellatrix_net)
```

---

## 4. Configuração de Providers LLM

```toml
# docker/orchestrator/config/providers.toml

[router]
# Slot "simple": tarefas rápidas e baratas
simple = "provider_a"
# Slot "complex": análise profunda e planejamento
complex = "provider_b"
# Slot "reasoning": chain-of-thought longo
reasoning = "provider_b"
# Slot "permissive": conteúdo ofensivo (Malware Dev)
permissive = "provider_a"

[providers.provider_a]
name = "DeepSeek Chat"
base_url = "https://api.deepseek.com/v1"
model = "deepseek-chat"
api_key_secret = "llm_provider_a_key"
max_tokens = 8192
timeout_secs = 30
# Parâmetros compatíveis OpenAI Chat Completions

[providers.provider_b]
name = "Anthropic Claude"
base_url = "https://api.anthropic.com"
model = "claude-sonnet-4-6"
api_key_secret = "llm_provider_b_key"
max_tokens = 16384
timeout_secs = 120
# Usa cliente Anthropic nativo (não OpenAI-compat)

# Para adicionar um novo provider:
# 1. Adicione [providers.nome] com os campos acima
# 2. Atribua ao slot desejado em [router]
# 3. Se a API é OpenAI-compatible, use base_url + model
# 4. Se tem cliente nativo, implemente LlmProvider em crates/infrastructure/
```

---

## 5. Configuração de Tools MCP

```toml
# docker/orchestrator/config/tools.toml

[tools.semgrep]
url = "http://semgrep:8081"
timeout_secs = 120
max_files_per_scan = 1000

[tools.nuclei]
url = "http://nuclei:8082"
timeout_secs = 300
default_severity = ["critical", "high", "medium"]

[tools.caido]
url = "http://caido:8080"
timeout_secs = 60

[tools.radare2]
url = "http://radare2:8083"
timeout_secs = 60

[tools.metasploit]
url = "http://metasploit:8084"
timeout_secs = 300

[tools.sqlmap]
url = "http://sqlmap:8085"
timeout_secs = 300

[tools.ffuf]
url = "http://ffuf:8086"
timeout_secs = 180

[tools.amass]
url = "http://amass:8087"
timeout_secs = 600

[tools.subfinder]
url = "http://subfinder:8088"
timeout_secs = 120

[tools.httpx]
url = "http://httpx:8089"
timeout_secs = 120

[tools.grype]
url = "http://grype:8090"
timeout_secs = 120

[tools.tor]
socks5_proxy = "socks5://tor:9050"
health_url = "http://tor:8091/health"
```

---

## 6. Setup de VMs Alvo (KVM)

### 6.1 Rede KVM

```bash
# Criar rede isolada para targets (sem acesso à internet)
cat > /tmp/target-net.xml << 'EOF'
<network>
  <name>bellatrix-targets</name>
  <bridge name='virbr-bel' stp='on' delay='0'/>
  <ip address='192.168.200.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.200.10' end='192.168.200.50'/>
    </dhcp>
  </ip>
</network>
EOF

virsh net-define /tmp/target-net.xml
virsh net-start bellatrix-targets
virsh net-autostart bellatrix-targets
```

### 6.2 Windows Target VM

```bash
# Baixar ISO Windows 10 LTSC (licença de avaliação 90 dias)
# https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise

# Criar VM
virt-install \
  --name windows-target-01 \
  --memory 8192 \
  --vcpus 4 \
  --disk path=/var/lib/libvirt/images/windows-target-01.qcow2,size=60,format=qcow2 \
  --cdrom /path/to/windows10.iso \
  --os-variant win10 \
  --network network=bellatrix-targets \
  --graphics spice \
  --video qxl \
  --boot cdrom,hd

# Após instalação, criar snapshot "clean"
virsh snapshot-create-as windows-target-01 "clean-install" \
  --description "Estado limpo pré-ataque" \
  --atomic

# Restaurar para estado limpo entre campanhas
virsh snapshot-revert windows-target-01 clean-install
```

### 6.3 Linux Target VM

```bash
# Ubuntu 22.04 com cloud-init
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
qemu-img convert -f qcow2 -O qcow2 jammy-server-cloudimg-amd64.img \
  /var/lib/libvirt/images/linux-target-01.qcow2
qemu-img resize /var/lib/libvirt/images/linux-target-01.qcow2 40G

# cloud-init para configurar usuário e SSH
cat > /tmp/user-data.yml << 'EOF'
#cloud-config
users:
  - name: target
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ssh-ed25519 AAAA... # sua chave pública
packages:
  - openssh-server
  - netcat-openbsd
EOF

virt-install \
  --name linux-target-01 \
  --memory 4096 \
  --vcpus 2 \
  --disk /var/lib/libvirt/images/linux-target-01.qcow2 \
  --cloud-init user-data=/tmp/user-data.yml \
  --os-variant ubuntu22.04 \
  --network network=bellatrix-targets \
  --import \
  --noautoconsole

virsh snapshot-create-as linux-target-01 "clean-install" --atomic
```

### 6.4 Acesso das tools às VMs

O container `orchestrator` tem acesso à rede `virbr-bel` via:
```yaml
# compose.yml — adicionar ao orchestrator
networks:
  bellatrix_net: {}
  kvm_targets:
    driver: macvlan
    driver_opts:
      parent: virbr-bel
```

---

## 7. Primeira Execução

### 7.1 Checklist obrigatório

```bash
# 1. Clonar e configurar secrets
git clone <repo> bellatrix-india
cd bellatrix-india
mkdir -p docker/secrets
echo "sk-..." > docker/secrets/llm_provider_a_key   # DeepSeek key
echo "sk-ant-..." > docker/secrets/llm_provider_b_key  # Anthropic key
chmod 600 docker/secrets/*

# 2. Build do workspace Rust
cargo build --workspace --release

# 3. Subir stack Docker
docker compose -f docker/compose.yml up -d

# 4. Verificar saúde de todos os containers
docker compose -f docker/compose.yml ps
./bin/bellatrix tools health

# 5. Verificar Qdrant
curl http://localhost:6333/health

# 6. Iniciar ingestão RAG (dados iniciais)
./scripts/ingest-rag.sh

# 7. Verificar collections criadas
curl http://localhost:6333/collections
```

### 7.2 Verificação de sanidade

```bash
# Teste básico: scan SAST em arquivo de exemplo
./bin/bellatrix scan sast --file tests/fixtures/vuln_php.php

# Teste básico: probe HTTP
./bin/bellatrix scan web --url http://testphp.vulnweb.com

# Teste de campanha mínima
./bin/bellatrix campaign start \
  --name "smoke-test" \
  --target "http://testphp.vulnweb.com" \
  --service appsec \
  --authorized
```

---

## 8. Variáveis de Ambiente

```bash
# .env (nunca comitar — adicionar ao .gitignore)

# Logging
RUST_LOG=info,bellatrix=debug

# Qdrant
QDRANT_URL=http://qdrant:6333

# SQLite
DATABASE_URL=sqlite:///data/sqlite/bellatrix.db

# Proxy de anonimização (padrão: tor)
HTTP_PROXY=socks5://tor:9050
HTTPS_PROXY=socks5://tor:9050

# KVM bridge IP (host)
KVM_BRIDGE_IP=192.168.200.1
```

---

## 9. Atualização

```bash
# Atualizar regras Nuclei
docker compose -f docker/compose.yml exec nuclei nuclei -update-templates

# Atualizar regras Semgrep
docker compose -f docker/compose.yml exec semgrep semgrep --update

# Rebuild após mudanças no código Rust
cargo build --workspace --release
docker compose -f docker/compose.yml restart orchestrator

# Re-ingestão incremental do RAG
./scripts/ingest-rag.sh --incremental
```
