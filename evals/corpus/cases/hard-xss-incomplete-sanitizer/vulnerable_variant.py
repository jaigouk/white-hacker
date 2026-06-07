import re


def render_comment(text):
    clean = re.sub(r"<script.*?>.*?</script>", "", text, flags=re.I)
    return f"<div>{clean}</div>"
