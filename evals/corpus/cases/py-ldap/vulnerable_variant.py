def search(conn, user):
    return conn.search_s("dc=x", 2, "(uid=" + user + ")")  # SINK ldap-injection
