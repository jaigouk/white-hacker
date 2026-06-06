def ingest(store, doc):
    store.add(doc)  # SINK rag-poisoning (no provenance check)
