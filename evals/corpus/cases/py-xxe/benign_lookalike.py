import lxml.etree as ET
def parse(xml):
    p = ET.XMLParser(resolve_entities=False, no_network=True)
    return ET.fromstring(xml, p)
