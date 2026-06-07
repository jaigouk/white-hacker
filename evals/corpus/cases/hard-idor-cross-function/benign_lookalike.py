def _load_invoice(db, invoice_id):
    return db.query("Invoice").get(invoice_id)


def get_invoice(db, current_user, invoice_id):
    invoice = _load_invoice(db, invoice_id)
    if invoice.owner_id != current_user.id:
        raise PermissionError("forbidden")
    return invoice.to_dict()
