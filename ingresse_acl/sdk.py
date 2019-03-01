VERSION = '0.2.2'

from ingresse_acl.client    import AclClient
from ingresse_acl.client    import AclException
from ingresse_acl.client    import AclError
from ingresse_acl.resources import SdkResource
from ingresse_acl.resources import User       as UserResource
from ingresse_acl.resources import Role       as RoleResource
from ingresse_acl.resources import Permission as PermissionResource
from ingresse_acl.resources import Resource   as ResourceResource
from ingresse_acl.resources import Context    as ContextResource

class BaseApp(object):
    token  = None
    client = None

    def _get_permission_params(self, item, permission, resource, resource_value,
        context=None, context_value=None):
        """ Get item id and Permissions dict

        Keyword Arguments:
        item           -- mixed (integer, string, resources.SdkResource)
        permission     -- mixed (integer, string, resources.Permission)
        resource       -- mixed (integer, string, resources.Resource)
        resource_value -- string
        context        -- mixed (integer, string, resources.Context)
        context_value  -- string

        Returns: tuple
        """
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
            """ Executes Batch"""
            pass

class IngresseACL(object):
    token = None

    def __init__(self, token, environment='production'):
        """ Initiate instance

        Keyword Arguments:
        token       -- string
        environment -- string
        """
        self.token  = token
        self.client = AclClient(environment)

        self.User = User()
        self.User.token  = self.token
        self.User.client = self.client

        self.Validate = Validate()
        self.Validate.token  = self.token
        self.Validate.client = self.client

        self.Role = Role()
        self.Role.token  = self.token
        self.Role.client = self.client

        self.BatchUser = BatchUser()
        self.BatchUser.token  = self.token
        self.BatchUser.client = self.client

        self.BatchRole = BatchRole()
        self.BatchRole.token  = self.token
        self.BatchRole.client = self.client


class Validate(BaseApp):

    def validate(self, user_id, permission, resource, resource_value="__ANY__",
        context=None, context_value="__ANY__"):

        query_params = {
            "ingresseId": user_id,
            "permission": permission,
            "resource": resource,
            "resourceValue": resource_value,
            "contextValue": context_value
        }

        if context:
            query_params.update({"context": context})

        return self.client.get(token=self.token, path=AclClient.VALIDATE,
            params=query_params)


class User(BaseApp):

    def list(self):
        """Return a user list

        Returns: list
        """
        resp = self.client.get(token=self.token, path=AclClient.USERS)
        return [UserResource(user) for user in resp]

    def get(self, user_term):
        """Return a user

        Keyword Arguments:
        user_term -- string - (Id or Email)

        Returns: resources.User
        """
        resp = self.client.get(token=self.token,
            path=AclClient.USERS_UNIQUE,
            path_params={"user_term":user_term})
        return UserResource(resp)

    def create(self, ingresse_id, email):
        """Create and return a user

        Keyword Arguments:
        ingresse_id -- integer - User id on Ingresse environment
        email       -- string

        Returns: resources.User
        """
        user_body = {
            'ingresseId': ingresse_id,
            'email': email
        }
        resp = self.client.post(token=self.token, body=user_body,
            path=AclClient.USERS)
        return UserResource(resp)

    def update(self, user, email=None):
        """Update a User

        Keyword Arguments:
        user  -- mixed (integer, string or resources.User)
        email -- string

        Returns: boolean
        """
        if isinstance(user, UserResource):
            email = user.email
            user  = user.id

        user_body = {"email":email}

        return self.client.put(token=self.token, body=user_body,
            path=AclClient.USERS_UNIQUE, path_params={"user_term":user})

    def remove(self, user):
        """Remove a user

        Keyword Arguments:
        user -- mixed (integer or resources.User)

        Returns: boolean
        """
        if isinstance(user, UserResource):
            user = user.id

        return self.client.delete(token=self.token,
            path=AclClient.USERS_UNIQUE, path_params={"user_term":user})

    def add_role(self, user, role):
        """Add a role to a user

        Keyword Arguments:
        user -- mixed (integer, string or resources.User)
        role -- mixed (integer, string or resources.Role)
        """
        if isinstance(user, UserResource):
            user = user.id

        if isinstance(role, RoleResource):
            role = role.id

        resp = self.client.post(token=self.token, body={"role": role},
            path=AclClient.USERS_ROLES, path_params={"user_term":user})

        return UserResource(resp)

    def remove_role(self, user, role):
        """Remove a role from a user

        Keyword Arguments:
        user -- mixed (integer, string or resources.User)
        role -- mixed (integer, string or resources.Role)

        Returns: boolean
        """
        if isinstance(user, UserResource):
            user = user.id

        if isinstance(role, RoleResource):
            role = role.id

        return self.client.delete(token=self.token,
            path=AclClient.USERS_ROLES_UNIQUE,
            path_params={"user_term":user, "role_id":role})

    def add_permission(self, user, permission, resource, resource_value,
        context=None, context_value=None):
        """Add a permission to a user

        Keyword Arguments:
        user           -- mixed (integer, string or resources.User)
        permission     -- mixed (integer, string or resources.Permission)
        resource       -- mixed (integer, string or resources.Resource)
        resource_value -- string
        context        -- mixed (integer, string or resources.Context)
        context_value  -- string

        Returns: boolean
        """
        user, body = self._get_permission_params(user, permission, resource,
            resource_value, context, context_value)

        return self.client.post(token=self.token, body=body,
            path=AclClient.USERS_PERMS, path_params={"user_term":user})

    def remove_permission(self, user, permission, resource, resource_value,
        context=None, context_value=None):
        """Remove a permission from a user

        Keyword Arguments:
        user           -- mixed (integer, string or resources.User)
        permission     -- mixed (integer, string or resources.Permission)
        resource       -- mixed (integer, string or resources.Resource)
        resource_value -- string
        context        -- mixed (integer, string or resources.Context)
        context_value  -- string

        Returns: boolean
        """
        user, param = self._get_permission_params(user, permission,
            resource, resource_value, context, context_value)

        return self.client.delete(token=self.token, params=param,
            path=AclClient.USERS_PERMS, path_params={"user_term":user})

class Role(BaseApp):

    def list(self):
        """Return a role list

        Returns: list
        """
        resp = self.client.get(token=self.token, path=AclClient.ROLES)
        return [RoleResource(user) for user in resp]

    def get(self, role_term):
        """Return a role

        Keyword Arguments:
        role_term -- string - (Id or Name)

        Returns: resources.Role
        """
        resp = self.client.get(token=self.token,
            path=AclClient.ROLES_UNIQUE,
            path_params={"role_term":role_term})
        return RoleResource(resp)

    def create(self, name, alias, description):
        """Create and return a role

        Keyword Arguments:
        name        -- string
        alias       -- string
        description -- string

        Returns: resources.Role
        """
        role_body = {
            'name': name,
            'alias': alias,
            'description': description
        }
        resp = self.client.post(token=self.token, body=role_body,
            path=AclClient.ROLES)
        return RoleResource(resp)

    def update(self, role, alias=None, description=None):
        """Update a Role

        Keyword Arguments:
        role        -- mixed (integer, string or resrouces.Role)
        alias       -- string
        description -- string

        Returns: boolean
        """
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

    def update_users(self, role, users):
        """Update role users

        Keyword Arguments:
        role_id     -- integer
        users       -- list

        Returns: boolean
        """
        if isinstance(role, RoleResource):
            role = role.id

        body = {
            "users": users
        }

        return self.client.put(token=self.token, body=body,
            path=AclClient.ROLES_USERS, path_params={"role_id":role})

    def remove(self, role):
        """Remove a Role

        Keyword Arguments:
        role -- mixed (integer, string or resrouces.Role)

        Returns: boolean
        """
        if isinstance(role, RoleResource):
            role = role.id

        return self.client.delete(token=self.token,
            path=AclClient.ROLES_UNIQUE, path_params={"role_term":role})

    def add_permission(self, role, permission, resource, resource_value,
        context=None, context_value=None):
        """Add a permission to a role

        Keyword Arguments:
        role           -- mixed (integer, string or resources.Role)
        permission     -- mixed (integer, string or resources.Permission)
        resource       -- mixed (integer, string or resources.Resource)
        resource_value -- string
        context        -- mixed (integer, string or resources.Context)
        context_value  -- string

        Returns: resources.Role
        """
        role, body = self._get_permission_params(role, permission, resource,
            resource_value, context, context_value)
        self.client.post(token=self.token, body=body,
            path=AclClient.ROLES_PERMS, path_params={"role_term":role})

        return self.get(role)

    def remove_permission(self, role, permission, resource, resource_value,
        context=None, context_value=None):
        """Remove a permission from a role

        Keyword Arguments:
        role           -- mixed (integer, string or resources.Role)
        permission     -- mixed (integer, string or resources.Permission)
        resource       -- mixed (integer, string or resources.Resource)
        resource_value -- string
        context        -- mixed (integer, string or resources.Context)
        context_value  -- string

        Returns: resources.Role
        """
        role, param = self._get_permission_params(role, permission,
            resource, resource_value, context, context_value)
        self.client.delete(token=self.token, params=param,
            path=AclClient.ROLES_PERMS, path_params={"role_term":role})

        return self.get(role)

class BatchUser(Batch):

    def __init__(self):
        """Initiates instance"""
        super(BatchUser, self).__init__()
        self._objs = []
        self.user  = None

    def set_user(self, user):
        """Set user to batch process

        Keyword Arguments:
        user -- mixed (integer or resources.User)
        """
        if isinstance(user, UserResource):
            user = user.id
        self.user  = user

    def add_permission(self, permission, resource, resource_value,
        context=None, context_value=None):
        """Add a permission to batch process

        Keyword Arguments:
        permission     -- mixed (integer, string or resources.Permission)
        resource       -- mixed (integer, string or resources.Resource)
        resource_value -- string
        context        -- mixed (integer, string or resources.Context)
        context_value  -- string
        """
        perm = self._get_permission_params(None, permission,
            resource, resource_value, context, context_value)
        self._objs.append(perm[1])

    def clear_permissions(self):
        """Clear a permissions from batch process"""
        self._objs = []

    def execute(self):
        """Execute batch process

        Returns: boolean
        """
        if not self.user:
            raise Exception("User must be setted")

        self.client.post(token=self.token, body=self._objs,
            path=AclClient.BATCH_USERS_PERM,
            path_params={"user_term":self.user})

        self.clear_permissions()

        return True

class BatchRole(Batch):

    def __init__(self):
        """Initiates instance"""
        super(BatchRole, self).__init__()
        self.role   = None
        self._perms = []
        self._roles = []

    def set_role(self, role):
        """Set role to batch process

        Keyword Arguments:
        role -- mixed (integer or resources.Role)
        """
        if isinstance(role, RoleResource):
            role = role.id
        self.role = role

    def add_permission(self, permission, resource, resource_value,
        context=None, context_value=None):
        """Add a permission to batch process

        Keyword Arguments:
        permission     -- mixed (integer, string or resources.Permission)
        resource       -- mixed (integer, string or resources.Resource)
        resource_value -- string
        context        -- mixed (integer, string or resources.Context)
        context_value  -- string
        """
        perm = self._get_permission_params(None, permission,
            resource, resource_value, context, context_value)
        self._perms.append(perm[1])

    def clear_permissions(self):
        """Clear a permissions from batch process"""
        self._perms = []

    def add_role(self, name, alias, description, system=False):
        """Add a role to batch process

        Keyword Arguments:
        name        -- string
        alias       -- string
        description -- string
        system      -- boolean
        """
        self._roles.append({
            'name': name,
            'alias': alias,
            'description': description,
            'system': system
        })

    def clear_roles(self):
        """Clear a roles from batch process"""
        self._roles = []

    def execute(self):
        """Execute batch process

        Returns: list
        """
        roles = []
        if self._roles:
            resp = self.__execute_roles()
            roles = [RoleResource(item) for item in resp]

        if self._perms:
            self.__execute_perms()

        return roles

    def __execute_perms(self):
        """Execute batch process from Permissions"""
        if not self.role:
            raise Exception("Role must be setted")

        self.client.post(token=self.token, body=self._perms,
            path=AclClient.BATCH_ROLES_PERM,
            path_params={"role_term":self.role})

        self.clear_permissions()

    def __execute_roles(self):
        """Execute batch process from Roles

        Returns: list
        """
        roles = self.client.post(token=self.token, body=self._roles,
            path=AclClient.BATCH_ROLES)

        self.clear_roles()

        return roles

