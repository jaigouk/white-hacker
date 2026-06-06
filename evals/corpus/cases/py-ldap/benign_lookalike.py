from ldap.filter import escape_filter_chars as esc
def search(conn, user):
    return conn.search_s("dc=x", 2, "(uid=" + esc(user) + ")")
