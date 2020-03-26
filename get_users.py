import gitlab
import os
from dotenv import load_dotenv
import ldap




def ldap_connect():
    conn = ldap.initialize(os.environ['LDAP_URI'])
    if os.getenv('LDAP_STARTTLS').lower() in {'yes', 'true', 'on'}:
        conn.start_tls_s()

    if os.getenv('LDAP_BIND_DN'):
        conn.bind_s(os.environ['LDAP_BIND_DN'], os.environ['LDAP_BIND_PW'])

    print(conn.whoami_s())

    return conn


def get_ldap_groups():
    '''Get LDAP user groups'''


if __name__ == '__main__':
    load_dotenv()
    ldap_conn = ldap_connect()

    with gitlab.Gitlab(os.environ['GITLAB_URL'], os.environ['GITLAB_TOKEN']) as gl:
        users = gl.users.list(as_list=False)
        for i, user in enumerate(users):
            print(i, user.username)
