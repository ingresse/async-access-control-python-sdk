class SdkResource(object):
    def get_dict(self):
        pass

class User(SdkResource):
    def __init__(self, user):
        self.id          = user.get("id")
        self.ingresse_id = user.get("ingresseId")
        self.email       = user.get("email")
        self.permissions = [ UserPermission(item) for item in user.get("permissions", []) ]
        self.roles       = [ Role(item) for item in user.get("roles", []) ]

    def get_dict(self):
        return {
            "id": self.id,
            "ingresseId": self.ingresse_id,
            "email": self.email
        }

class Role(SdkResource):
    def __init__(self, role):
        self.id          = role.get("id")
        self.name        = role.get("name")
        self.alias       = role.get("alias")
        self.description = role.get("description")
        self.system      = role.get("system")
        self.permissions = [ RolePermission(item) for item in role.get("permissions", []) ]

    def get_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "alias": self.alias,
            "description": self.description,
            "system": self.system
        }


class Permission(SdkResource):
    def __init__(self, permission):
        self.id          = permission.get("id")
        self.name        = permission.get("name")
        self.alias       = permission.get("alias")
        self.description = permission.get("description")

    def get_dict(self):
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
        self.permission     = permission.get("permission")
        self.resource       = permission.get("resourceName")
        self.resource_value = permission.get("resourceValue")
        self.context        = permission.get("contextName")
        self.context_value  = permission.get("contextValue")

    def get_dict(self):
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
