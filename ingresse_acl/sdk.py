VERSION = '0.0.1'

from client    import AclClient
from resources import SdkResource
from resources import User       as UserResource
from resources import Role       as RoleResource
from resources import Permission as PermissionResource
from resources import Resource   as ResourceResource
from resources import Context    as ContextResource

class BaseApp(object):
    token  = None
    client = None

    def _get_permission_params(self, item, permission, resource, resource_value,
        context=None, context_value=None):
        if isinstance(item, SdkResource):
            item = item.id

        if isinstance(permission, PermissionResource):
            permission = permission.id

        if isinstance(resource, ResourceResource):
            resource = resource.id

        if isinstance(context, ContextResource):
            context = context.id

        params = {
            "permission": permission,
            "resource": resource,
            "resourceValue": resource_value
        }

        if context is not None:
            params.update({
                "context": context,
                "contextValue": context_value
            })

        return item, params

class Batch(BaseApp):
        def execute(self):
            pass

class IngresseACL(object):
    token = None

    def __init__(self, token, environment='prod'):
        self.token  = token
        self.client = AclClient(environment)

        self.User = User()
        self.User.token  = self.token
        self.User.client = self.client

        self.Role = Role()
        self.Role.token  = self.token
        self.Role.client = self.client

        self.BatchUser = BatchUser()
        self.BatchUser.token  = self.token
        self.BatchUser.client = self.client

        self.BatchRole = BatchRole()
        self.BatchRole.token  = self.token
        self.BatchRole.client = self.client

class User(BaseApp):

    def list(self):
        resp = self.client.get(token=self.token, path=AclClient.USERS)
        return [UserResource(user) for user in resp]

    def get(self, user_term):
        resp = self.client.get(token=self.token,
            path=AclClient.USERS_UNIQUE,
            path_params={"user_term":user_term})
        return UserResource(resp)

    def create(self, ingresse_id, email):
        user_body = {
            'ingresseId': ingresse_id,
            'email': email
        }
        resp = self.client.post(token=self.token, body=user_body,
            path=AclClient.USERS)
        return UserResource(resp)

    def update(self, user, email=None):
        if isinstance(user, UserResource):
            email = user.email
            user  = user.id

        user_body = {"email":email}

        return self.client.put(token=self.token, body=user_body,
            path=AclClient.USERS_UNIQUE, path_params={"user_term":user})

    def remove(self, user):
        if isinstance(user, UserResource):
            user = user.id

        return self.client.delete(token=self.token,
            path=AclClient.USERS_UNIQUE, path_params={"user_term":user})

    def add_role(self, user, role):
        if isinstance(user, UserResource):
            user = user.id

        if isinstance(role, RoleResource):
            role = role.id

        resp = self.client.post(token=self.token, body={"role": role},
            path=AclClient.USERS_ROLES, path_params={"user_term":user})

        return UserResource(resp)

    def remove_role(self, user, role):
        if isinstance(user, UserResource):
            user = user.id

        if isinstance(role, RoleResource):
            role = role.id

        resp = self.client.delete(token=self.token,
            path=AclClient.USERS_ROLES_UNIQUE,
            path_params={"user_term":user, "role_id":role})

        return self.get(user)

    def add_permission(self, user, permission, resource, resource_value,
        context=None, context_value=None):

        user, body = self._get_permission_params(user, permission, resource,
            resource_value, context, context_value)
        self.client.post(token=self.token, body=body,
            path=AclClient.USERS_PERMS, path_params={"user_term":user})

        return self.get(user)

    def remove_permission(self, user, permission, resource, resource_value,
        context=None, context_value=None):
        user, param = self._get_permission_params(user, permission,
            resource, resource_value, context, context_value)
        self.client.delete(token=self.token, params=param,
            path=AclClient.USERS_PERMS, path_params={"user_term":user})

        return self.get(user)

class Role(BaseApp):

    def list(self):
        resp = self.client.get(token=self.token, path=AclClient.ROLES)
        return [RoleResource(user) for user in resp]

    def get(self, role_term):
        resp = self.client.get(token=self.token,
            path=AclClient.ROLES_UNIQUE,
            path_params={"role_term":role_term})
        return RoleResource(resp)

    def create(self, name, alias, description):
        role_body = {
            'name': name,
            'alias': alias,
            'description': description
        }
        resp = self.client.post(token=self.token, body=role_body,
            path=AclClient.ROLES)
        return RoleResource(resp)

    def update(self, role, alias=None, description=None):
        if isinstance(role, RoleResource):
            alias       = role.alias
            description = role.description
            role        = role.id

        role_body = {
            "alias": alias,
            "description": description
        }

        return self.client.put(token=self.token, body=role_body,
            path=AclClient.ROLES_UNIQUE, path_params={"role_term":role})

    def remove(self, role):
        if isinstance(role, RoleResource):
            role = role.id

        return self.client.delete(token=self.token,
            path=AclClient.ROLES_UNIQUE, path_params={"role_term":role})

    def add_permission(self, role, permission, resource, resource_value,
        context=None, context_value=None):

        role, body = self._get_permission_params(role, permission, resource,
            resource_value, context, context_value)
        self.client.post(token=self.token, body=body,
            path=AclClient.ROLES_PERMS, path_params={"role_term":role})

        return self.get(role)

    def remove_permission(self, role, permission, resource, resource_value,
        context=None, context_value=None):
        role, param = self._get_permission_params(role, permission,
            resource, resource_value, context, context_value)
        self.client.delete(token=self.token, params=param,
            path=AclClient.ROLES_PERMS, path_params={"role_term":role})

        return self.get(role)

class BatchUser(Batch):

    def __init__(self):
        super(BatchUser, self).__init__()
        self._objs = []
        self.user  = None

    def set_user(self, user):
        if isinstance(user, UserResource):
            user = user.id
        self.user  = user

    def add_permission(self, permission, resource, resource_value,
        context=None, context_value=None):
        perm = self._get_permission_params(None, permission,
            resource, resource_value, context, context_value)
        self._objs.append(perm[1])

    def clear_permissions(self):
        self._objs = []

    def execute(self):
        if not self.user:
            raise Exception("User must be setted")

        self.client.post(token=self.token, body=self._objs,
            path=AclClient.BATCH_USERS_PERM,
            path_params={"user_term":self.user})

        self.clear_permissions()

        return True

class BatchRole(Batch):

    def __init__(self):
        super(BatchRole, self).__init__()
        self.role   = None
        self._perms = []
        self._roles = []

    def set_role(self, role):
        if isinstance(role, RoleResource):
            role = role.id
        self.role = role

    def add_permission(self, permission, resource, resource_value,
        context=None, context_value=None):
        perm = self._get_permission_params(None, permission,
            resource, resource_value, context, context_value)
        self._perms.append(perm[1])

    def clear_permissions(self):
        self._perms = []

    def add_role(self, name, alias, description, system=False):
        self._roles.append({
            'name': name,
            'alias': alias,
            'description': description,
            'system': system
        })

    def clear_roles(self):
        self._roles = []

    def execute(self):
        roles = []
        if self._roles:
            resp = self.__execute_roles()
            roles = [RoleResource(item) for item in resp]

        if self._perms:
            self.__execute_perms()

        return roles

    def __execute_perms(self):
        if not self.role:
            raise Exception("Role must be setted")

        self.client.post(token=self.token, body=self._perms,
            path=AclClient.BATCH_ROLES_PERM,
            path_params={"role_term":self.role})

        self.clear_permissions()

    def __execute_roles(self):
        roles = self.client.post(token=self.token, body=self._roles,
            path=AclClient.BATCH_ROLES)

        self.clear_roles()

        return roles

