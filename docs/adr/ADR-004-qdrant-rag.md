# ADR-004: Qdrant como Vector Database para RAG Local

**Status:** Aceito  
**Data:** 2026-04-19  
**Decisores:** equipe Bellatrix India

---

## Contexto

A plataforma precisa de busca semântica sobre grandes volumes de dados de inteligência (CVEs, ATT&CK TTPs, LOLBAS, etc.). Alternativas avaliadas:

| Opção | Prós | Contras |
|---|---|---|
| Qdrant | OSS, performático, API REST, Docker nativo, sem telemetria | Menos maduro que pgvector |
| pgvector (Postgres) | Muito maduro, SQL familiar | Overhead de Postgres para use case simples |
| Chroma | Python-first, simples | Menos performático em escala, sem Rust client nativo |
| Weaviate | Feature-rich | Complexo, Docker image pesada |
| Pinecone / Weaviate Cloud | Gerenciado | Dados saem do host — inaceitável |

---

## Decisão

Usar **Qdrant** como vector database local em Docker.

**Razões determinantes:**
1. **Local-first e sem telemetria** — dados de inteligência nunca saem do host
2. **Client Rust nativo** (`qdrant-client` crate) — integração natural com o stack
3. **API REST HTTP** — simples de testar e debugar sem dependências
4. **Collections tipadas** — cada fonte de inteligência em collection separada
5. **Filtros por metadata** — permite queries como "CVEs com CVSS >= 9 em Python"
6. **Docker image oficial leve** (~150MB)

**Collections definidas:** ver `docs/RAG_STRATEGY.md`

**Modelo de embedding:** configurável via `providers.toml` — qualquer provider com suporte a embed. Padrão: modelo do slot `simple` configurado.

---

## Consequências

**Positivas:**
- Queries semânticas em <100ms mesmo com milhões de vetores
- Zero dados de inteligência fora do host
- Client Rust elimina dependência de serviço externo
- Filtros por metadata reduzem ruído nos resultados

**Negativas:**
- Dimensão dos vetores deve ser fixada no momento da criação da collection
- Trocar de modelo de embedding requer re-ingestão completa
- Sem suporte a full-text search nativo (complementado por SQLite FTS5)

**Mitigação:**
- Dimensão configurada via `providers.toml` antes da primeira ingestão
- Script `ingest-rag.sh --full` para re-ingestão quando necessário
- SQLite FTS5 para busca exata por CVE ID, TTP ID, etc.
