def build(system, retrieved):
    return system + "\n" + retrieved  # SINK prompt-injection (untrusted concat into instructions)
