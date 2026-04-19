# ADR-003: MCP (JSON-RPC 2.0) como Interface Universal de Tools

**Status:** Aceito  
**Data:** 2026-04-19  
**Decisores:** equipe Bellatrix India

---

## Contexto

Os agentes LLM precisam invocar ferramentas de segurança heterogêneas (Semgrep, Nuclei, Metasploit, etc.). Cada ferramenta tem sua própria CLI, API, ou formato de output. Precisamos de uma interface uniforme que:
- Seja invocável pelo agente LLM de forma estruturada
- Permita adicionar novas tools sem mudar o código do agente
- Suporte autodescoberta e documentação de schema
- Seja compatível com o protocolo MCP (usado por Claude, Cursor, etc.)

---

## Decisão

Adotar o **Model Context Protocol (MCP)** com transporte JSON-RPC 2.0 via HTTP como interface universal para todas as tools.

**Formato de tool call:**
```json
{
  "jsonrpc": "2.0",
  "id": "uuid",
  "method": "tools/call",
  "params": {
    "name": "tool_name",
    "arguments": { ... }
  }
}
```

Cada container de tool expõe um servidor HTTP MCP. O `mcp_router` registra as tools na inicialização via `tools/list`. Novos tools são descobertos automaticamente se o container expõe o endpoint MCP.

**MCP wrappers:** tools sem servidor HTTP próprio recebem um sidecar Python/Go leve que:
1. Aceita JSON-RPC via HTTP
2. Traduz para chamada CLI da ferramenta
3. Parseia output e retorna JSON estruturado

---

## Consequências

**Positivas:**
- Interface uniforme independente da ferramenta subjacente
- LLM pode invocar qualquer tool com o mesmo padrão
- Schema autodocumentado via `tools/list`
- Compatível com o ecossistema MCP (Claude, Cursor, etc.)
- Fácil extensão: implementar trait `McpTool` + registrar

**Negativas:**
- Wrappers adicionam latência (~1-5ms por call)
- Wrapper Python precisa ser mantido por cada ferramenta
- Debugging mais complexo (2 hop: orchestrator → router → container)

**Mitigação:**
- Template padrão de wrapper reduz esforço de manutenção
- Audit log no router registra toda call com latência
- Ferramenta de diagnóstico: `./bin/bellatrix tools health --verbose`
