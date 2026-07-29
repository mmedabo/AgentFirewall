"""DEMO ONLY — a deliberately vulnerable agent backend, used to exercise
AgentFirewall's deployed-agent guardrail checks. Do NOT ship anything like this.

It reproduces two real-world classes of bug:
  * check-after-act quota enforcement (the Bolt.new refresh exploit), and
  * an agent tool that runs arbitrary user code (the "chatbot writes Python" case).
"""
from framework import agent, app, current_user  # imaginary web framework


@app.post("/chat")
def handle_chat(request):
    prompt = request.json["prompt"]

    # BUG (TOCTOU): the expensive agent call runs BEFORE we verify the user can
    # afford it. On a refresh/retry the queued prompt is processed before the
    # credit check completes, so a zero-credit user gets a free prompt.
    result = agent.run(prompt)

    if not current_user.has_credits():
        return {"error": "out of credits"}
    current_user.deduct_credits(1)
    return {"result": result}


# BUG (excessive agency): a food-ordering bot should not be able to run code.
@agent.tool("run_python")
def run_python(code: str) -> str:
    """Execute arbitrary Python and return the output."""
    return str(eval(code))  # user input drives code execution
