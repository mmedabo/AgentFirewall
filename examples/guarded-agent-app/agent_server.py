"""The vulnerable-agent-app, fixed with AgentFirewall runtime guardrails.

Compare with examples/vulnerable-agent-app: quota is authorized and reserved
BEFORE the agent runs (and is idempotent by request id, so a refresh can't replay),
and the agent is confined to its ordering tools — no arbitrary code execution.
"""
from framework import agent, app  # imaginary web framework

from agentfirewall.guardrails import (
    InMemoryQuota,
    InputGuard,
    PreconditionGate,
    QuotaExceeded,
    ScopePolicy,
)

# Confine McBot to exactly its business tools; deny code execution by default.
guard = InputGuard(ScopePolicy.for_tools("search_menu", "place_order"))
# Authorize + reserve quota before the agent runs; idempotent by request id.
gate = PreconditionGate(InMemoryQuota(default=0))


@app.post("/chat")
def handle_chat(request):
    user_id = request.user.id
    prompt = request.json["prompt"]
    request_id = request.headers.get("Idempotency-Key")

    # Scope: reject prompt-injection / off-mission input before doing anything.
    guard.check_input(prompt).raise_if_blocked()

    try:
        # Check-before-act: quota is consumed atomically BEFORE agent.run, and a
        # refresh/replay with the same request_id returns the stored result.
        result = gate.run(user_id, lambda: agent.run(prompt), idempotency_key=request_id)
    except QuotaExceeded:
        return {"error": "out of credits"}, 402
    return {"result": result}


@agent.tool_call_hook
def before_tool_call(name, arguments):
    # Every tool the model wants to call is checked against the scope policy;
    # a call to run_python / shell is denied even if the model tries it.
    guard.check_tool_call(name, arguments).raise_if_blocked()
