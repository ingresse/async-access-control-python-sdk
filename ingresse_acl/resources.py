class SdkResource(object):
    async def get_dict(self):
        """Return dict with resource values"""
        pass

class User(SdkResource):
    def __init__(self, user):
        """Initiate instance

        Keyword Arguments:
        user -- dict
        """
        self.id          = user.get("id")
        self.ingresse_id = user.get("ingresseId")
        self.email       = user.get("email")
        self.permissions = [ UserPermission(item) for item in user.get("permissions", []) ]
        self.roles       = [ Role(item) for item in user.get("roles", []) ]

    async def get_dict(self):
        """Return dict with resource values

        Return: dict
        """
        return {
            "id": self.id,
            "ingresseId": self.ingresse_id,
            "email": self.email
        }

class Role(SdkResource):
    def __init__(self, role):
        """Initiate instance

        Keyword Arguments:
        role -- dict
        """
        self.id          = role.get("id")
        self.name        = role.get("name")
        self.alias       = role.get("alias")
        self.description = role.get("description")
        self.system      = role.get("system")
        self.permissions = [ RolePermission(item) for item in role.get("permissions", []) ]
        self.users       = [ User(item) for item in role.get("users", []) ]

    async def get_dict(self):
        """Return dict with resource values

        Return: dict
        """
        return {
            "id": self.id,
            "name": self.name,
            "alias": self.alias,
            "description": self.description,
            "system": self.system,
            "users": self.users,

        }


class Permission(SdkResource):
    def __init__(self, permission):
        """Initiate instance

        Keyword Arguments:
        permission -- dict
        """
        self.id          = permission.get("id")
        self.name        = permission.get("name")
        self.alias       = permission.get("alias")
        self.description = permission.get("description")

    async def get_dict(self):
        """Return dict with resource values

        Return: dict
        """
        return {
            "id": self.id,
            "name": self.name,
            "alias": self.alias,
            "description": self.description
        }

class Resource(Permission):
    def __init__(self, resource):
        super(Resource, self).__init__(resource)

class Context(Permission):
    def __init__(self, context):
        super(Context, self).__init__(context)

class RolePermission(SdkResource):
    def __init__(self, permission):
        """Initiate instance

        Keyword Arguments:
        permission -- dict
        """
        self.permission     = permission.get("permission")
        self.resource       = permission.get("resourceName")
        self.resource_value = permission.get("resourceValue")
        self.context        = permission.get("contextName")
        self.context_value  = permission.get("contextValue")

    async def get_dict(self):
        """Return dict with resource values

        Return: dict
        """
        return {
            "permission":    self.permission,
            "resource":      self.resource,
            "resourceValue": self.resource_value,
            "context":       self.context,
            "contextValue":  self.context_value
        }


class UserPermission(RolePermission):
    def __init__(self, permission):
        super(UserPermission, self).__init__(permission)
