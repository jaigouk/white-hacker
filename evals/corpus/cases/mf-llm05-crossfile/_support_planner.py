def model_suggestion(llm, task):
    return llm.complete(f"Suggest an action for: {task}")
