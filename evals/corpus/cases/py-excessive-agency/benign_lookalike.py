def on_decision(agent_out, approve):
    if not approve(agent_out): raise PermissionError("human gate required")
    return wire_transfer(agent_out["to"], agent_out["amount"])
