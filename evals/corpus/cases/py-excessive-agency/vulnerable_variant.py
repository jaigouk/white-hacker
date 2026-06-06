def on_decision(agent_out):
    return wire_transfer(agent_out["to"], agent_out["amount"])  # SINK excessive-agency
