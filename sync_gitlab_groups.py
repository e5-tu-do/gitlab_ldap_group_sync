import gitlab
from gitlab.exceptions import GitlabGetError
import os
from dotenv import load_dotenv
import ldap
import logging
from collections import namedtuple
import sys


MOCK = not os.getenv('GITLAB_SYNC', False)
if not MOCK:
    # must be mock at the moment
    sys.exit(1)

LDAPGroup = namedtuple('LDAPGroup', 'dn cn members')
LDAPUser = namedtuple('LDAPUser', 'dn uid mail')
ACCESS = gitlab.DEVELOPER_ACCESS


log = logging.getLogger('giblab_ldap_sync')
log.setLevel(logging.INFO)

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    '%(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S'
))

logging.getLogger().addHandler(handler)


class Mock:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def __getattr__(self, name):
        if name in self.kwargs:
            return self.kwargs[name]
        return Mock()

    def __call__(self, *args, **kwargs):
        return Mock()

    def __repr__(self):
        return f'Mock({self.args}, {self.kwargs})'


def ldap_connect():
    conn = ldap.initialize(os.environ['LDAP_URI'])
    if os.getenv('LDAP_STARTTLS').lower() in {'yes', 'true', 'on'}:
        conn.start_tls_s()

    conn.simple_bind_s(os.getenv('LDAP_BIND_DN'), os.getenv('LDAP_BIND_PW'))

    return conn


def get_ldap_groups(ldap_conn, min_members=1):
    '''Get LDAP groups'''
    base = os.environ['LDAP_GROUP_BASE']
    user_base = os.environ['LDAP_USER_BASE']
    log.info(f'Using group base {base}')

    group_filter = os.getenv('LDAP_GROUP_FILTER')
    if group_filter:
        log.info(f'Using group filter {group_filter}')

    result = ldap_conn.search_s(
        base, ldap.SCOPE_SUBTREE, group_filter, ['cn', 'member']
    )

    log.info(f'Found {len(result)} ldap groups')

    groups = {
        dn: LDAPGroup(
            cn=g['cn'][0].decode('utf-8'),
            dn=dn,
            members=[
                m.decode('utf-8')
                for m in g.get('member', [])
                if user_base in m.decode('utf-8')]
        )
        for dn, g in result
        if g.get('cn') and len(g.get('member', [])) > min_members
    }
    log.info(f'Found {len(groups)} ldap groups with atleast {min_members} members')

    return groups


def get_ldap_users(ldap_conn):
    '''Get LDAP users'''
    base = os.environ['LDAP_USER_BASE']
    log.info(f'Using group base {base}')

    user_filter = os.getenv('LDAP_USER_FILTER')
    if user_filter:
        log.info(f'Using user filter {user_filter}')

    result = ldap_conn.search_s(
        base, ldap.SCOPE_SUBTREE, user_filter, ['dn', 'uid', 'mail']
    )
    log.info(f'Found {len(result)} ldap users')

    users = {
        dn: LDAPUser(
            dn=dn,
            uid=u['uid'][0].decode('utf-8'),
            mail=u['mail'][0].decode('utf-8'),
        )
        for dn, u in result
        if all([u.get('mail'), u.get('uid')])
    }
    log.info(f'Found {len(users)} ldap users with email and uid set')

    return users


def create_group(gl, name):
    log.info(f'Creating gitlab group {name}')
    if MOCK:
        return Mock(name=name)
    else:
        return gl.groups.create({'name': name, 'path': name})


def add_member(group, username, access_level, gl_users):
    if username not in gl_users:
        log.info(f'Skipping user {username} because he/she never logged into gitlab')
        return

    log.info(f'Adding {username} to group {group.name}')
    if not MOCK:
        group.members.create(dict(user_id=username, access_level=access_level))


def remove_member(group, username):
    log.info(f'Removing {username} from group {group.name}')
    if not MOCK:
        group.members.delete(dict(member_id=username))


def get_or_create_group(gl, name):
    '''Query gitlab for group `name`, if not exists create it.
    Returns the group object and if it is new or not.
    '''
    try:
        group = gl.groups.get(name)
        return group, False
    except GitlabGetError as e:
        if 'Group Not Found' in str(e):
            return create_group(gl, name=name), True
        raise


def sync_ldap_group(gl, ldap_group, ldap_users, gl_users):
    log.info(f'Syncing LDAP group {ldap_group.dn}')
    gl_group, new = get_or_create_group(gl, ldap_group.cn)

    # if new group, we can just add all members
    if new:
        log.info(f'Filling new group {ldap_group.cn} with ldap members')
        for member in ldap_group.members:
            ldap_user = ldap_users[member]
            add_member(gl_group, ldap_user.uid, ACCESS, gl_users)
    else:
        gl_members = set(u.username for u in gl_group.members.list(as_list=False))
        ldap_members = set(ldap_users[u].uid for u in ldap_group.members)
        to_add = ldap_members - gl_members
        to_remove = gl_members - ldap_members

        for username in to_add:
            add_member(gl_group, username, ACCESS, gl_users)

        for username in to_remove:
            remove_member(gl_group, username)


def main():
    load_dotenv()
    ldap_conn = ldap_connect()
    ldap_groups = get_ldap_groups(ldap_conn)
    ldap_users = get_ldap_users(ldap_conn)
    ldap_conn.unbind_s()

    with gitlab.Gitlab(os.environ['GITLAB_URL'], os.environ['GITLAB_TOKEN']) as gl:

        gl_users = {u.username: u for u in gl.users.list(as_list=False)}
        log.info(f'Found {len(gl_users)} gitlab users')

        for ldap_group in ldap_groups.values():
            sync_ldap_group(gl, ldap_group, ldap_users, gl_users)


if __name__ == '__main__':
    main()
