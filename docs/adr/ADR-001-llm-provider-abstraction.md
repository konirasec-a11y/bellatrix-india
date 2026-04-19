# ADR-001: Abstração Provider-Agnostic para LLMs

**Status:** Aceito  
**Data:** 2026-04-19  
**Decisores:** equipe Bellatrix India

---

## Contexto

A plataforma precisa usar múltiplos provedores de LLM simultaneamente para diferentes tipos de tarefa:
- Tarefas simples e rápidas: provedores baratos com menor latência
- Raciocínio complexo e multi-step: provedores premium com reasoning nativo
- Conteúdo ofensivo (Malware Dev): provedores com políticas mais permissivas
- Ambiente air-gapped ou offline: LLM local via Ollama

Vincular o código a um provedor específico criaria dependência de vendor, impossibilitaria troca por questões de custo/disponibilidade/política, e dificultaria testes unitários.

---

## Decisão

Definir o trait `LlmProvider` em `crates/application` como o único ponto de acesso a LLMs no sistema. Implementações concretas ficam em `crates/infrastructure/llm/`. O `LlmRouter` em `crates/llm_router` seleciona a implementação correta baseado em `TaskComplexity`.

```rust
#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn name(&self) -> &str;
    fn supports_reasoning(&self) -> bool;
    fn cost_tier(&self) -> CostTier;
    async fn complete(&self, req: CompletionRequest) -> anyhow::Result<CompletionResponse>;
    async fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>>;
}

pub enum TaskComplexity {
    Simple,
    Complex,
    Reasoning,
    Permissive,
}
```

A configuração de qual provider atende qual slot é feita em `providers.toml` — sem rebuild necessário para trocar de provider.

**Provedores suportados via OpenAI-compat (base_url customizável):**
- DeepSeek (chat e reasoner)
- Qualquer modelo Ollama
- OpenAI GPT
- Groq, Together AI, Fireworks AI

**Provedores com cliente nativo:**
- Anthropic Claude (API diferente de OpenAI)

---

## Consequências

**Positivas:**
- Troca de provider sem mudança de código
- Testes com `MockLlmProvider` triviais
- Suporte a múltiplos providers simultaneamente
- Fallback configurável por slot

**Negativas:**
- Interface mais genérica pode não expor features exclusivas de um provider (ex: tool_use nativo da Anthropic)
- Overhead de manutenção ao adicionar providers com APIs muito diferentes

**Mitigação:**
- Providers que precisam de features específicas podem adicionar métodos opcionais via trait extension
- O wrapper OpenAI-compat cobre ~80% dos casos sem código adicional
