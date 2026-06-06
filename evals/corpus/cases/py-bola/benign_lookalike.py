def get_order(db, order_id, session):
    return db.orders.find(order_id, owner=session.user_id)
