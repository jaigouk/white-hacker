def get_doc(db, current_user, doc_id):
    if not current_user.is_active:
        raise PermissionError("inactive account")
    doc = db.get_doc(doc_id)
    return doc.body
