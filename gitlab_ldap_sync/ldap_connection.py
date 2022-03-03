import ldap
import os
from .utils import getenvbool


def ldap_connect():
    conn = ldap.initialize(os.environ['LDAP_URI'])
    if getenvbool('LDAP_STARTTLS'):
        conn.start_tls_s()

    conn.simple_bind_s(os.getenv('LDAP_BIND_DN'), os.getenv('LDAP_BIND_PW'))

    return conn
