"""DEMO — trusts a peer agent's card without verifying its signature (ASI07)."""
import requests


def load_peer(agent_url):
    card = requests.get(f"{agent_url}/.well-known/agent.json").json()
    # BUG: the agent card is used to delegate tasks with verification disabled,
    # so any host can impersonate 'billing-agent' or shadow its skills.
    return register_agent(card, verify_signature=False, trust_all_agents=True)
