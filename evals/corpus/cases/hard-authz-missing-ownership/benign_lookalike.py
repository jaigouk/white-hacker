def get_doc(db, current_user, doc_id):
    if not current_user.is_active:
        raise PermissionError("inactive account")
    doc = db.get_doc(doc_id)
    if doc.owner_id != current_user.id:
        raise PermissionError("not owner")
    return doc.body
