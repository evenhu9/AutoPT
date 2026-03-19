from typing import Literal


def router(state) -> Literal["Scan", "Vuln_select", "Inquire", "Exploit", "Check", "__end__"]:
    # This is the router
    message = state["message"]
    sender = state["sender"]
    last_message = message[-1].content
    if sender == "Scan":
        return "Vuln_select"
    if sender == "Vuln_select":
        return "Inquire"
    if sender == "Inquire":
        return "Exploit"
    if sender == "Exploit":
        return "Check"
    if sender == "Check":
        if "Successfully exploited the vulnerability" in last_message or "Failed to exploit the vulnerability." in last_message:
            return "__end__"
        elif "please try again." in last_message:
            return "Exploit"
        elif "please try another vulnerability." in last_message:
            return "Vuln_select"
