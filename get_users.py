import gitlab
from gitlab.exceptions import GitlabGetError
import os
from dotenv import load_dotenv
import ldap
import logging
from collections import namedtuple


MOCK = not os.getenv('GITLAB_SYNC', False)

LDAPGroup = namedtuple('LDAPGroup', 'dn cn members')
LDAPUser = namedtuple('LDAPUser', 'dn uid mail')


log = logging.getLogger('giblab_ldap_sync')
log.setLevel(logging.INFO)

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    '%(asctime)s|%(levelname)8s|%(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S.%f'
))

logging.getLogger().addHandler(handler)


class Mock:
    def __getattr__(self):
        return Mock()

    def __call__(self, *args, **kwargs):
        return Mock()


def ldap_connect():
    conn = ldap.initialize(os.environ['LDAP_URI'])
    if os.getenv('LDAP_STARTTLS').lower() in {'yes', 'true', 'on'}:
        conn.start_tls_s()

    conn.simple_bind_s(os.getenv('LDAP_BIND_DN'), os.getenv('LDAP_BIND_PW'))

    return conn


def get_ldap_groups(ldap_conn, min_members=1):
    '''Get LDAP groups'''
    base = os.environ['LDAP_GROUP_BASE']
    log.info(f'Using group base {base}')

    group_filter = os.getenv('LDAP_GROUP_FILTER')
    if group_filter:
        log.info(f'Using group filter {group_filter}')

    result = ldap_conn.search_s(
        base, ldap.SCOPE_SUBTREE, group_filter, ['cn', 'member']
    )

    log.info(f'Found {len(result)} ldap groups')

    groups = [
        LDAPGroup(cn=g['cn'][0].decode('utf-8'), dn=dn, members=g.get('member', []))
        for dn, g in result
        if g.get('cn') and len(g.get('member', [])) > min_members
    ]
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

    users = [
        LDAPUser(dn=dn, uid=u['uid'], mail=u['mail'])
        for dn, u in result
        if all([u.get('mail'), u.get('uid')])
    ]
    log.info(f'Found {len(users)} ldap users with email and uid set')

    return users


def create_group(gl, name):
    logging.info(f'Creating gitlab group {name}')
    if MOCK:
        return Mock(name)
    else:
        return gl.groups.create({'name': name, 'path': name})


def add_member(group, username, access_level):
    logging.info(f'Adding {username} as {access_level} to group {group}')
    if not MOCK:
        group.members.create(dict(user_id=username, access_level=access_level))


def get_or_create_group(gl, name):
    '''Query gitlab for group `name`, if not exists create it.
    Returns the group object and if it is new or not.
    '''
    try:
        group = gl.groups.get(name)
        return group, False
    except GitlabGetError as e:
        if 'Group Not Found' in str(e):
            log.info(f'No group {name} found in gitlab')
            return create_group(gl, name=name), True
        raise


def sync_ldap_group(gl, ldap_group, ldap_users):
    log.info(f'Syncing LDAP group {ldap_group.dn}')
    gitlab_group, new = get_or_create_group(ldap_group.cn)

    # if new group, we can just add all members
    if new:
        for member in ldap_group.members:
            username = ldap_users[member]


def main():
    load_dotenv()
    ldap_conn = ldap_connect()
    ldap_groups = get_ldap_groups(ldap_conn)
    ldap_users = get_ldap_users(ldap_conn)

    with gitlab.Gitlab(os.environ['GITLAB_URL'], os.environ['GITLAB_TOKEN']) as gl:
        for ldap_group in ldap_groups:
            sync_ldap_group(gl, ldap_group, ldap_users)


if __name__ == '__main__':
    main()
