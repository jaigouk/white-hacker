from jinja2 import Template
def render(name):
    return Template("Hi {{ n }}").render(n=name)
