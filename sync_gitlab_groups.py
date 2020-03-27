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

LDAPGroup = namedtuple('LDAPGroup', 'dn cn members parent')
LDAPUser = namedtuple('LDAPUser', 'dn uid mail publickeys')
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


def get_ldap_groups(ldap_conn, min_members=0):
    '''Get LDAP groups and build a tree of the hierarchy'''
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

    groups = []

    for dn, g in result:
        n_members = len(g.get('member', []))
        if g.get('cn') is None or n_members < min_members:
            log.info(f'Group {dn} has no cn or too few members ({n_members})')
            continue

        cn = g['cn'][0].decode('utf-8')
        members = [
            m.decode('utf-8')
            for m in g.get('member', [])
            if user_base in m.decode('utf-8')
        ]
        parent = ','.join(dn.split(',')[1:])
        if dn == base:
            parent = None

        groups.append(LDAPGroup(dn=dn, cn=cn, members=members, parent=parent))

    log.info(f'Found {len(groups)} ldap groups with cn and atleast {min_members} members')

    # sort groups by hierarchy level
    groups.sort(key=lambda g: 0 if g.parent is None else len(g.parent.split(',')))

    # build tree
    tree = {'group': None, 'children': {}}
    group_lookup = {base: tree}

    for group in groups:
        # group is base
        if group.parent is None:
            tree['group'] = group
            group_lookup[group.dn] = tree
        else:
            g = {'group': group, 'children': {}}
            group_lookup[group.dn] = g
            group_lookup[group.parent]['children'][group.dn] = g

    return tree


def get_ldap_users(ldap_conn):
    '''Get LDAP users'''
    base = os.environ['LDAP_USER_BASE']
    log.info(f'Using group base {base}')

    user_filter = os.getenv('LDAP_USER_FILTER')
    if user_filter:
        log.info(f'Using user filter {user_filter}')

    result = ldap_conn.search_s(
        base, ldap.SCOPE_SUBTREE, user_filter, ['dn', 'uid', 'mail', 'sshPublicKey']
    )
    log.info(f'Found {len(result)} ldap users')

    users = {
        dn: LDAPUser(
            dn=dn,
            uid=u['uid'][0].decode('utf-8'),
            mail=u['mail'][0].decode('utf-8'),
            # publickeys can be multiple ldap entries and multiple keys in a single entry
            publickeys=[keys.split(b'\n') for keys in u.get('sshPublicKey', [])]
        )
        for dn, u in result
        if all([u.get('mail'), u.get('uid')])
    }
    log.info(f'Found {len(users)} ldap users with email and uid set')

    return users


def create_group(gl, name, parent=None):
    log.info(
        f'Creating gitlab group {name}'
        + (f' as subgroup of {parent.cn}' if parent is not None else '')
    )
    new_group = {'name': name, 'path': name}
    if parent is not None:
        gl_parent = gl.groups.get(parent.cn)
        new_group['parent_id'] = gl_parent
    if MOCK:
        return Mock(**new_group)
    else:
        return gl.groups.create(new_group)


def add_member(group, user, access_level):
    log.info(f'Adding {user.username} with id {user.id} to group {group.name}')
    if not MOCK:
        group.members.create(dict(user_id=user.id, access_level=access_level))


def remove_member(group, user):
    log.info(f'Removing {user.username} with id {user.id} from group {group.name}')
    if not MOCK:
        group.members.delete(dict(member_id=user.id))


def get_or_create_group(gl, name, parent=None):
    '''Query gitlab for group `name`, if not exists create it.
    Returns the group object and if it is new or not.
    '''
    try:
        group = gl.groups.get(name)
        return group, False
    except GitlabGetError as e:
        if 'Group Not Found' in str(e):
            return create_group(gl, name=name, parent=parent), True
        raise


def sync_ldap_group(gl, ldap_group, ldap_users, gl_users, parent=None):
    log.info(f'Syncing LDAP group {ldap_group.dn}')
    if parent is not None:
        log.info(f'Group is subgroup of {parent.cn}')

    gl_group, new = get_or_create_group(gl, ldap_group.cn, parent=parent)

    if new:
        gl_members = set()
    else:
        gl_members = set(u.username for u in gl_group.members.list(as_list=False))

    ldap_members = set(ldap_users[u].uid for u in ldap_group.members)
    to_add = ldap_members - gl_members
    to_remove = gl_members - ldap_members

    for username in to_add:
        user = gl_users.get(username)
        if user is None:
            log.info(f'Skipping {username} because he/she never logged into gitlab')
            continue
        add_member(gl_group, user, ACCESS)

    for username in to_remove:
        remove_member(gl_group, gl_users[username])


def print_group_tree(tree, level=0):
    '''Print a nice tree view of the found ldap groups'''
    n_members = 0 if tree['group'] is None else len(tree['group'].members)
    if tree['group'] is not None:
        print(' ' * level * 2, tree['group'].cn, n_members)

    for subtree in tree['children'].values():
        print_group_tree(subtree, level=level+1)


def sync_group_tree(gl, tree, ldap_users, gl_users, parent=None):
    '''Sync memberships of gitlab groups with ldap groups'''

    if tree['group'] is not None:
        sync_ldap_group(gl, tree['group'], ldap_users, gl_users, parent=parent)

    for subtree in tree['children'].values():
        sync_group_tree(gl, subtree, ldap_users, gl_users, parent=tree.get('group'))


def main():
    load_dotenv()
    ldap_conn = ldap_connect()
    ldap_group_tree = get_ldap_groups(ldap_conn)
    log.info('Build the following group tree (name, n_members):')
    print_group_tree(ldap_group_tree)
    ldap_users = get_ldap_users(ldap_conn)
    ldap_conn.unbind_s()

    with gitlab.Gitlab(os.environ['GITLAB_URL'], os.environ['GITLAB_TOKEN']) as gl:
        gl_users = {u.username: u for u in gl.users.list(as_list=False)}
        log.info(f'Found {len(gl_users)} gitlab users')
        sync_group_tree(gl, ldap_group_tree, ldap_users, gl_users)


if __name__ == '__main__':
    main()
