# Agent Frameworks Cheatsheet

> Per-framework map of where the four canonical components live (LLM call,
> tool registration, memory store, sandbox / approval gate). Used by the recon
> agent to skip the discovery step on well-known frameworks and to seed
> Semgrep rule authors when adding coverage for a new framework.

Each section gives:

- **Detect:** signatures that `tools/detect_stack.py` checks for.
- **LLM call:** where prompts go to the model.
- **Tool registration:** how an agent picks up a callable.
- **Memory:** how prior turns persist.
- **Approval / sandbox:** human-in-the-loop and execution boundary.
- **High-yield grep targets:** what Phase 3 should search first.

## MCP (Model Context Protocol)

- **Detect:** `@modelcontextprotocol/sdk`, `McpServer`, `CallToolRequestSchema`,
  `StdioServerTransport`, `ListToolsRequestSchema`.
- **LLM call:** out-of-band (MCP servers expose tools to *another* LLM client;
  the server itself rarely calls the LLM).
- **Tool registration:**
  - JS/TS: `server.tool(name, schema, handler)` or
    `server.setRequestHandler(CallToolRequestSchema, async (req) => ...)`.
  - Tool *descriptions* go into the agent's system context — these are the
    primary tool-poisoning surface.
- **Memory:** none directly; the consumer client owns memory.
- **Approval / sandbox:** none built-in. Each tool is responsible for its own
  guardrails.
- **High-yield grep targets:**
  - `CallToolRequestSchema` handlers — argument validation absent?
  - `description:` field interpolated from external data?
  - `return { content: [{ type: "text", text: \`${external}\` }] }` — A3 surface.

## LangChain (Python)

- **Detect:** `from langchain`, `@langchain/`, `langchain_core`.
- **LLM call:**
  - `ChatOpenAI()`, `ChatAnthropic()`, etc. → `.invoke()` / `.ainvoke()`.
  - `RunnableSequence(...).invoke()`.
- **Tool registration:**
  - `@tool` decorator: `def my_tool(x: str) -> str: ...`.
  - `Tool(name=, func=, description=)` legacy constructor.
- **Memory:**
  - `ConversationBufferMemory`, `ConversationSummaryMemory`,
    `VectorStoreRetrieverMemory`.
  - `RedisChatMessageHistory` (persisted across processes).
- **Approval / sandbox:** none by default. `AgentExecutor(handle_parsing_errors=,
  max_iterations=, return_intermediate_steps=)` are the only knobs;
  `max_iterations` is the soft cap on runaway loops.
- **High-yield grep targets:**
  - `ChatPromptTemplate.from_messages([("system", f"...{x}...")])` — A5.
  - `@tool` body that calls `os.system`, `subprocess.run`, `eval`, `open` — RCE.
  - `memory.save_context({...})` with non-literal payload — A6.
  - `AgentExecutor(...)` missing `max_iterations` — A10 / DoS surface.

## CrewAI (Python)

- **Detect:** `from crewai`, `CrewAI`.
- **LLM call:** delegated to LangChain `ChatOpenAI` etc.
- **Tool registration:**
  - `Task(description=, expected_output=, tools=[tool1, tool2])`.
  - `Crew(agents=[...], tasks=[...], tools=...)` for crew-wide tools.
- **Memory:** `memory=True` on `Crew(...)` flips short-term memory on.
  Long-term via crewai_tools.
- **Approval / sandbox:** none built-in.
- **High-yield grep targets:**
  - `Crew(tools=all_tools)` — privilege over-grant.
  - `Task.output` passed into `subprocess.run` / `os.system` — A3.

## AutoGen (Python)

- **Detect:** `from autogen`, `AssistantAgent`, `register_function`.
- **LLM call:** internal — `llm_config=` on each `AssistantAgent`.
- **Tool registration:**
  - `register_function(my_fn, caller=assistant, executor=user_proxy)`.
  - On a `ConversableAgent`, `register_for_llm` / `register_for_execution`.
- **Memory:** message history per `ConversableAgent`.
- **Approval / sandbox:**
  - `human_input_mode=` on every agent. Values: `"ALWAYS"`, `"TERMINATE"`,
    `"NEVER"`. `"NEVER"` is the high-risk default for the executor agent.
  - `code_execution_config={"use_docker": True}` for sandboxing.
- **High-yield grep targets:**
  - `human_input_mode="NEVER"` on the executor agent.
  - `code_execution_config={"use_docker": False, ...}` — host RCE surface.
  - Functions registered via `register_function` whose body calls shell sinks.

## OpenHands (formerly OpenDevin) — Python

- **Detect:** `from openhands.`, `OpenDevin`, `openhands-ai`.
- **LLM call:** `openhands.llm.LLM` wrapper.
- **Tool registration:** runtime hooks; tools live under
  `openhands.runtime.plugins`.
- **Memory:** event stream, persisted via the runtime store.
- **Approval / sandbox:**
  - `permission_mode = "auto" | "prompt" | "deny"` — `"auto"` is the dangerous
    default.
  - `sandbox = "auto" | "docker" | "local" | "remote"` — `"auto"` silently
    falls back to local when no Docker is available.
- **High-yield grep targets:**
  - `permission_mode = "auto"`.
  - `sandbox = "auto"` paired with no availability check.
  - Filesystem actions running without workspace clamp.

## openai-agents (Python)

- **Detect:** `from agents import`, `Runner.run(`, `openai.Agents`.
- **LLM call:** `Runner.run(agent, input, max_turns=)` /
  `Runner.run_sync(...)`.
- **Tool registration:**
  - `@function_tool` decorator.
  - `Agent(name=, instructions=, tools=[...])`.
- **Memory:** managed by the framework via the `Agent` session; opaque to
  user code.
- **Approval / sandbox:** none built-in. Guardrails live in the `instructions`
  string.
- **High-yield grep targets:**
  - `Runner.run(agent, input)` without `max_turns` — A10 / DoS.
  - `@function_tool def f(x: str): subprocess.run(x, shell=True)` — RCE.
  - Tool decorator on a function that touches the file system or network.

## pydantic-ai (Python)

- **Detect:** `from pydantic_ai`, `pydantic-ai`.
- **LLM call:** `Agent.run(...)`, `Agent.run_sync(...)`.
- **Tool registration:**
  - `agent.tool` decorator (function-as-tool with Pydantic schema).
- **Memory:** message history is explicit (passed in / returned).
- **Approval / sandbox:** none built-in.
- **High-yield grep targets:**
  - `@agent.tool` body that shells out.
  - System prompt constructed with f-string + run-time data.

## semantic-kernel (Python / .NET)

- **Detect:** `semantic_kernel`, `Microsoft.SemanticKernel`.
- **LLM call:** `Kernel.invoke()`, `Kernel.invoke_prompt()`.
- **Tool registration:**
  - Python: `@kernel_function`.
  - .NET: `[KernelFunction]` attribute.
- **Memory:** `SemanticTextMemory` + connectors (Azure AI Search, Qdrant, …).
- **Approval / sandbox:** none built-in; planners route through tools without
  approval by default.
- **High-yield grep targets:**
  - `@kernel_function` body that calls `subprocess` / `os.system` / `exec`.
  - `Plan` execution that pipes `result` back into a new prompt without
    sanitization.

## agno / phidata (Python)

- **Detect:** `from agno.`, `from phi.agent`, `phidata`.
- **LLM call:** `Agent(...).print_response(...)`,
  `Agent(...).run(...)`.
- **Tool registration:**
  - `tools=[tool1, tool2]` on `Agent(...)`.
  - `@tool` decorator (agno's variant).
- **Memory:** `AgentMemory` / `AgentStorage` (Postgres, SQLite).
- **Approval / sandbox:** none built-in.
- **High-yield grep targets:**
  - Built-in tools with broad surface: `ShellTools`, `PythonTools`,
    `FileTools` — check if they are present and unconstrained.
  - `memory.add(...)` with non-literal payload.

## Claude Agent SDK (Python / TS)

- **Detect:** `claude_agent_sdk`, `ClaudeSDKClient`, `@anthropic-ai/claude-agent-sdk`.
- **LLM call:** internal — `ClaudeSDKClient.query(...)`.
- **Tool registration:** MCP-compatible (see MCP section).
- **Memory:** session-managed by the SDK.
- **Approval / sandbox:**
  - `permission_mode = "default" | "acceptEdits" | "plan" | "bypassPermissions"`.
  - `allowedTools = [...]`.
- **High-yield grep targets:**
  - `permission_mode = "bypassPermissions"`.
  - `allowedTools` left at the catch-all default.

---

## How to add a new framework

1. Add detection signatures to
   [tools/detect_stack.py](../../tools/detect_stack.py) `FRAMEWORK_SIGS` and to
   `AGENT_FRAMEWORKS` set.
2. Add the four-row block here (LLM call, tool reg, memory, approval/sandbox).
3. Add Semgrep rules to
   [rules/semgrep/agent-frameworks.yaml](../../rules/semgrep/agent-frameworks.yaml),
   tagged with `metadata.framework: <name>`.
4. If the framework has a non-obvious unsafe default, add a rule to
   [rules/semgrep/agent-defaults.yaml](../../rules/semgrep/agent-defaults.yaml)
   with `metadata.default_check: true`.
5. Add grep targets to
   [skills/03-taint/ai-agent-flows.md](../03-taint/ai-agent-flows.md) under the
   relevant A1–A10 pattern.

Single source of truth: this file. If the four-row block doesn't capture a
framework's risk surface, that's the gap to widen.
