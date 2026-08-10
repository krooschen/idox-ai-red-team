# Agentic Architecture Approaches for RedTeamer Chat Assistant

This document compares the different approaches for implementing the agentic architecture behind the RedTeamer chat assistant, and records the rationale for the chosen approach.

---

## Background

The RedTeamer UI needed an embedded chat assistant capable of:
- Listing and generating attack scenarios
- Triggering attacks and monitoring job status
- Running evaluations and reviewing results
- Configuring agent settings

Rather than a simple Q&A chatbot, the assistant needed to **act** — calling internal APIs, reading database state, and orchestrating multi-step workflows. This requires an agentic architecture where the LLM can invoke tools and reason over results.

Three approaches were evaluated: **Tool Calling**, **MCP (Model Context Protocol)**, and **Skill Frameworks**.

---

## Approach 1 — Tool Calling (Native LLM Function Calling)

### How it works

The LLM is given a list of tool definitions (name, description, input schema). When the LLM decides to use a tool, it returns a structured `tool_use` block instead of plain text. The application executes the tool and returns the result back to the LLM, which continues reasoning until it produces a final text response.

```
User message
    │
    ▼
LLM (with tool definitions in prompt)
    │  decides to call a tool
    ▼
Application executes tool (DB query, HTTP call, etc.)
    │  returns result
    ▼
LLM reasons over result → final response
```

### Implementation in RedTeamer

Implemented directly inside `routers/chat.py`:
- 10 tools defined: `list_scenarios`, `generate_scenario`, `trigger_attack`, `trigger_multiple_attacks`, `get_attack_status`, `get_job_status`, `list_attacks`, `run_evaluation`, `list_evaluations`, `update_agent_url`
- Two provider loops: `_run_anthropic()` for Anthropic API, `_run_openai()` for OpenAI / Azure OpenAI / OpenAI-compatible
- Tool execution in `_execute_tool()` — direct access to SQLAlchemy DB session and `httpx` HTTP client
- Provider selected via `EVALUATOR_PROVIDER` env var

### Pros
- Simple: everything runs in the same process, no network overhead between tool definition and execution
- Full access to DB session and internal state without serialization
- Works with all major LLM providers (Anthropic, OpenAI, Azure, compatible endpoints)
- Easy to add new tools — one function + one entry in the `TOOLS` list
- No external dependencies or infrastructure required

### Cons
- Tightly coupled to the API server process — tools cannot be used by external agents
- Tool definitions must be maintained in sync with the application logic

### When to use
- Single-service deployment where the chat is embedded in the same app
- No requirement for external agents to share the same tools
- Rapid iteration on tool capabilities

---

## Approach 2 — MCP (Model Context Protocol)

### How it works

MCP is Anthropic's open protocol for exposing tools and resources from a **server** to an **LLM client**. The MCP server runs as a separate process; the LLM client (e.g., Claude Desktop, Cursor, a custom app) connects to it over stdio or HTTP/SSE and discovers available tools dynamically.

```
LLM Client (e.g., Claude Desktop, custom app)
    │
    │  MCP Protocol (stdio / HTTP+SSE)
    ▼
MCP Server (separate process)
    │
    ▼
Tools / Resources / Prompts
```

### Applied to RedTeamer

The api-server would be refactored (or a separate process added) as an MCP server exposing `list_scenarios`, `trigger_attack`, etc. The chat assistant would become an MCP client connecting to this server.

### Pros
- Tools become reusable across different LLM clients (Claude Desktop, Cursor, any MCP-compatible app)
- Clean separation of concerns — tool logic lives in its own service
- Standardized protocol means external tools/clients can plug in without custom code
- If the chat UI is ever separated from the API server, MCP provides the bridge

### Cons
- Overhead: every tool call crosses a process boundary (stdio or network)
- More infrastructure: requires managing an additional MCP server process
- For a single embedded chat assistant, the separation adds complexity without benefit
- MCP is primarily a **client → server** protocol (LLM calls tools); it does not address **agent ↔ agent** peer communication

### When to use
- The same tools need to be available in multiple LLM clients (Claude Desktop AND custom UI AND Cursor, etc.)
- Tools need to be maintained and deployed independently of the chat UI
- The chat assistant is extracted from the API server into a standalone service

---

## Approach 3 — Skill Frameworks (LangChain, LlamaIndex, etc.)

### How it works

Frameworks like LangChain or LlamaIndex wrap the tool-calling pattern in a higher-level abstraction. Tools are defined as "skills" or "tools" within the framework, and the framework manages the agent loop, memory, and multi-step reasoning.

```
User message
    │
    ▼
Framework Agent (LangChain AgentExecutor, LlamaIndex ReActAgent, etc.)
    │  selects skill
    ▼
Skill / Tool function
    │
    ▼
Framework handles multi-step loop, memory, output parsing
```

### Applied to RedTeamer

Replace the custom `_run_anthropic()` / `_run_openai()` loops with a LangChain or LlamaIndex agent. Define tools as LangChain `@tool` functions wrapping the existing `_execute_tool` logic.

### Pros
- Rich ecosystem: built-in memory, RAG, chain-of-thought, multi-agent patterns
- Handles edge cases in the agent loop (max retries, output parsing, structured output)
- Easier to compose complex multi-step workflows

### Cons
- Heavy dependency: introduces a large framework with its own abstractions, versioning, and breaking changes
- Overkill for a focused tool set — the 10 tools in RedTeamer do not need RAG or chain-of-thought orchestration
- Adds indirection between tool definition and execution, making debugging harder
- Framework-specific agent loop may conflict with custom provider support (Azure OpenAI, OpenAI-compatible endpoints)

### When to use
- Complex multi-hop reasoning chains (e.g., auto-research → generate → test → evaluate, fully automated)
- Need built-in RAG, long-term memory, or vector retrieval
- Building a general-purpose AI assistant, not a focused domain tool

---

## Approach 4 — A2A (Agent-to-Agent Protocol)

> Note: A2A was not evaluated as an implementation option for the chat assistant itself, but is relevant for the broader system architecture.

### How it works

A2A is Google's open protocol (released April 2025) for standardized peer-to-peer communication between AI agents. Each agent exposes:
- An **Agent Card** at `/.well-known/agent.json` describing capabilities
- A **task endpoint** for submitting work
- **SSE streaming** for long-running task updates

```
Third-party Agent (A2A Client)
    │
    │  A2A Protocol (HTTP / SSE)
    ▼
RedTeamer (A2A Server)
    ├── api-server
    └── attack-agent
```

### Applied to RedTeamer

The entire RedTeamer system (api-server + attack-agent) can be exposed as an A2A-compliant agent. Third-party enterprise platforms or AI orchestrators could discover RedTeamer's capabilities and submit red-team tasks without custom integration.

Implementation would add a thin adapter layer (`routers/a2a.py`) on top of the existing REST API — the existing DB, job execution, and evaluation logic would not change.

### Pros
- Standardized interface for enterprise platform integration (Salesforce Agentforce, SAP, etc.)
- Built-in async task streaming solves the job-completion notification problem natively
- Enables RedTeamer to be listed in A2A-compatible agent marketplaces
- Existing REST API and UI continue to work unchanged

### Cons
- A2A spec is very new (April 2025); adoption is still forming
- Adds protocol overhead if only used internally
- Multi-worker deployments require additional state sharing (Redis) for SSE streams

### When to use
- Selling RedTeamer to enterprise customers who use A2A-compatible platforms
- Exposing RedTeamer as a callable service in a multi-agent security orchestration pipeline
- Required by an AI agent marketplace

---

## Decision Summary

| Criterion | Tool Calling | MCP | Skill Framework | A2A |
|---|---|---|---|---|
| Implementation complexity | Low | Medium | Medium | Medium |
| External infrastructure needed | None | MCP server process | None | None (adapter only) |
| Reusable by external clients | No | Yes (MCP clients) | No | Yes (A2A clients) |
| Multi-provider LLM support | Yes | Depends on client | Partial | N/A (transport layer) |
| Appropriate for embedded chat | **Best fit** | Overkill | Overkill | N/A |
| Appropriate for external agent access | No | Partial | No | **Best fit** |
| Current adoption | Universal | Growing (Claude ecosystem) | Mature | Early (enterprise) |

### Chosen approach: Tool Calling

**Reason**: RedTeamer's chat assistant is embedded in the same FastAPI application. Tool Calling gives direct, low-overhead access to the database and internal services. There is no cross-service boundary to cross, and no requirement for the tools to be shared with other LLM clients at this time.

**Future path**: If RedTeamer needs to be callable by third-party agents or enterprise platforms, adding an A2A adapter layer on top of the existing REST API is the recommended next step. This does not require changing the Tool Calling architecture of the embedded chat assistant.

---

## References

- [Anthropic Tool Use Documentation](https://docs.anthropic.com/en/docs/build-with-claude/tool-use)
- [OpenAI Function Calling](https://platform.openai.com/docs/guides/function-calling)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- [Google A2A Protocol](https://google.github.io/A2A/)
- [LangChain Agents](https://python.langchain.com/docs/concepts/agents/)
