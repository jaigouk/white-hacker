import lxml.etree as ET
def parse(xml):
    p = ET.XMLParser(resolve_entities=True)  # SINK xxe
    return ET.fromstring(xml, p)
