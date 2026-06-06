from jinja2 import Template
def render(name):
    return Template("Hi " + name).render()  # SINK ssti
