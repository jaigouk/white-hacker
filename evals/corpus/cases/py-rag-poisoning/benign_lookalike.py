def ingest(store, doc, trusted):
    if not trusted(doc.source): raise ValueError("untrusted source")
    store.add(doc)
