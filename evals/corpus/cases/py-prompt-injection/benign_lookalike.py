def build(system, retrieved):
    return system + "\n<untrusted>\n" + spotlight(retrieved) + "\n</untrusted>"

def spotlight(x):
    return x.replace("<", "&lt;")
