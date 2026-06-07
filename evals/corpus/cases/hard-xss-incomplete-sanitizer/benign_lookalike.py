import html


def render_comment(text):
    return f"<div>{html.escape(text)}</div>"
