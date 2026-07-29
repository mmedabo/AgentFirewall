// DEMO ONLY — quota enforced in the browser, which a user can trivially bypass
// by replaying the request. AgentFirewall flags this as client-side enforcement.

export function canSubmitPrompt(user) {
  // The only gate before calling the agent lives here, on the client.
  if (user.credits <= 0) {
    showOutOfCreditsModal();
    return false;
  }
  return true;
}

async function onSubmit(prompt, user) {
  if (!canSubmitPrompt(user)) return;
  await fetch("/chat", { method: "POST", body: JSON.stringify({ prompt }) });
}
