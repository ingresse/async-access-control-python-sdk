import json
import unittest
from unittest import mock

from ingresse_acl.client import AclClient, AclError, AclException
from ingresse_acl.resources import Context as ContextResource
from ingresse_acl.resources import Permission as PermissionResource
from ingresse_acl.resources import Resource as ResourceResource
from ingresse_acl.resources import Role as RoleResource
from ingresse_acl.resources import User as UserResource
from ingresse_acl.sdk import *


class testBatch(unittest.TestCase):
    def test_method_execute(self):
        self.assertEqual(None, Batch().execute())


class testBaseApp(unittest.TestCase):
    def test_method_get_permission_params_with_objects(self):
        item = UserResource({"id": 12})
        permission = PermissionResource({"id": 13})
        resource = ResourceResource({"id": 14})
        context = ContextResource({"id": 15})

        class MyTest(BaseApp):
            def method(self, *args, **kargs):
                return self._get_permission_params(*args, **kargs)

        user, perm = MyTest().method(
            item,
            permission,
            resource,
            "value1",
            context=context,
            context_value="value2",
        )

        self.assertEqual(12, user)
        self.assertEqual(13, perm.get("permission"))
        self.assertEqual(14, perm.get("resource"))
        self.assertEqual("value1", perm.get("resourceValue"))
        self.assertEqual(15, perm.get("context"))
        self.assertEqual("value2", perm.get("contextValue"))

    def test_method_get_permission_params_with_objects_no_context(self):
        item = UserResource({"id": 12})
        permission = PermissionResource({"id": 13})
        resource = ResourceResource({"id": 14})

        class MyTest(BaseApp):
            def method(self, *args, **kargs):
                return self._get_permission_params(*args, **kargs)

        user, perm = MyTest().method(item, permission, resource, "value1")

        self.assertEqual(12, user)
        self.assertEqual(13, perm.get("permission"))
        self.assertEqual(14, perm.get("resource"))
        self.assertEqual("value1", perm.get("resourceValue"))
        self.assertEqual(None, perm.get("context"))
        self.assertEqual(None, perm.get("contextValue"))

    def test_method_get_permission_params(self):
        item = 12
        permission = 13
        resource = 14
        context = 15

        class MyTest(BaseApp):
            def method(self, *args, **kargs):
                return self._get_permission_params(*args, **kargs)

        user, perm = MyTest().method(
            item,
            permission,
            resource,
            "value1",
            context=context,
            context_value="value2",
        )

        self.assertEqual(12, user)
        self.assertEqual(13, perm.get("permission"))
        self.assertEqual(14, perm.get("resource"))
        self.assertEqual("value1", perm.get("resourceValue"))
        self.assertEqual(15, perm.get("context"))
        self.assertEqual("value2", perm.get("contextValue"))

    def test_method_get_permission_params_no_context(self):
        item = 12
        permission = 13
        resource = 14

        class MyTest(BaseApp):
            def method(self, *args, **kargs):
                return self._get_permission_params(*args, **kargs)

        user, perm = MyTest().method(item, permission, resource, "value1")

        self.assertEqual(12, user)
        self.assertEqual(13, perm.get("permission"))
        self.assertEqual(14, perm.get("resource"))
        self.assertEqual("value1", perm.get("resourceValue"))
        self.assertEqual(None, perm.get("context"))
        self.assertEqual(None, perm.get("contextValue"))


class testIngresseACL(unittest.TestCase):
    @mock.patch("ingresse_acl.client.AclClient")
    def test_instance(self, mock_client):
        token = "MyToken"
        instance = IngresseACL(token)

        self.assertEqual(instance.token, token)
        self.assertIsInstance(instance.User, User)
        self.assertIsInstance(instance.Role, Role)
        self.assertIsInstance(instance.BatchUser, BatchUser)
        self.assertIsInstance(instance.BatchRole, BatchRole)


class testValidation(unittest.TestCase):
    @mock.patch("ingresse_acl.client.AclClient")
    def test_validate(self, mock_client):
        user_id = 1234
        permission = "perm"
        resource = "my-respurce"
        resource_val = 54321
        context = "my-context"
        context_val = 433987

        mock_client.get.return_value = True

        params = {
            "ingresseId": user_id,
            "permission": permission,
            "resource": resource,
            "resourceValue": resource_val,
            "contextValue": context_val,
            "context": context,
        }

        token = "MyToken"
        instance = Validate()
        instance.token = token
        instance.client = mock_client

        response = instance.validate(
            user_id, permission, resource, resource_val, context, context_val
        )

        mock_client.get.assert_called_with(
            token=token, path=AclClient.VALIDATE, params=params
        )

        self.assertIsInstance(response, bool)
        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_validate_fail(self, mock_client):
        user_id = 1234
        permission = "perm"
        resource = "my-respurce"
        resource_val = 54321
        context = "my-context"
        context_val = 433987

        mock_client.get.return_value = False

        params = {
            "ingresseId": user_id,
            "permission": permission,
            "resource": resource,
            "resourceValue": resource_val,
            "contextValue": context_val,
            "context": context,
        }

        token = "MyToken"
        instance = Validate()
        instance.token = token
        instance.client = mock_client

        response = instance.validate(
            user_id, permission, resource, resource_val, context, context_val
        )

        mock_client.get.assert_called_with(
            token=token, path=AclClient.VALIDATE, params=params
        )

        self.assertIsInstance(response, bool)
        self.assertFalse(response)


class testUser(unittest.TestCase):
    @mock.patch("ingresse_acl.client.AclClient")
    def test_list(self, mock_client):

        mock_client.get.return_value = USER_LIST

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.list()

        mock_client.get.assert_called_with(token=token, path=AclClient.USERS)

        self.assertIsInstance(response, list)
        self.assertEqual(2, len(response))

        for item in response:
            self.assertIsInstance(item, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_get_with_id(self, mock_client):

        mock_client.get.return_value = USER_LIST[0]
        term = USER_LIST[0].get("id")

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.get(term)

        mock_client.get.assert_called_with(
            token=token, path=AclClient.USERS_UNIQUE, path_params={"user_term": term}
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_get_with_email(self, mock_client):

        mock_client.get.return_value = USER_LIST[0]
        term = USER_LIST[0].get("email")

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.get(term)

        mock_client.get.assert_called_with(
            token=token, path=AclClient.USERS_UNIQUE, path_params={"user_term": term}
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_create(self, mock_client):

        mock_client.post.return_value = USER_LIST[0]
        iid = USER_LIST[0].get("ingresseId")
        email = USER_LIST[0].get("email")

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.create(iid, email)

        mock_client.post.assert_called_with(
            token=token, body={"ingresseId": iid, "email": email}, path=AclClient.USERS
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_update_with_object(self, mock_client):

        user = UserResource(USER_LIST[0])

        mock_client.put.return_value = True

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.update(user)

        mock_client.put.assert_called_with(
            token=token,
            body={"email": user.email},
            path=AclClient.USERS_UNIQUE,
            path_params={"user_term": user.id},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_update_with_id(self, mock_client):

        user = UserResource(USER_LIST[0])

        mock_client.put.return_value = True

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.update(user.id, email=user.email)

        mock_client.put.assert_called_with(
            token=token,
            body={"email": user.email},
            path=AclClient.USERS_UNIQUE,
            path_params={"user_term": user.id},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_update_with_email(self, mock_client):

        user = UserResource(USER_LIST[0])

        mock_client.put.return_value = True

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.update(user.email, email=user.email)

        mock_client.put.assert_called_with(
            token=token,
            body={"email": user.email},
            path=AclClient.USERS_UNIQUE,
            path_params={"user_term": user.email},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_with_object(self, mock_client):

        user = UserResource(USER_LIST[0])

        mock_client.delete.return_value = True

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.remove(user)

        mock_client.delete.assert_called_with(
            token=token, path=AclClient.USERS_UNIQUE, path_params={"user_term": user.id}
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_with_id(self, mock_client):

        user = UserResource(USER_LIST[0])

        mock_client.delete.return_value = True

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.remove(user.id)

        mock_client.delete.assert_called_with(
            token=token, path=AclClient.USERS_UNIQUE, path_params={"user_term": user.id}
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_with_email(self, mock_client):

        user = UserResource(USER_LIST[0])

        mock_client.delete.return_value = True

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.remove(user.email)

        mock_client.delete.assert_called_with(
            token=token,
            path=AclClient.USERS_UNIQUE,
            path_params={"user_term": user.email},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_get_roles_with_object(self, mock_client):
        user = UserResource(USER_LIST[0])
        mock_client.get.return_value = ROLE_LIST[0]

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.get_roles(user)

        mock_client.get.assert_called_with(
            token=token,
            path=AclClient.USERS_ROLES,
            params={},
            path_params={"user_term": user.id},
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_get_roles_with_id(self, mock_client):
        user = UserResource(USER_LIST[0])
        mock_client.get.return_value = ROLE_LIST[0]

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.get_roles(user.id)

        mock_client.get.assert_called_with(
            token=token,
            path=AclClient.USERS_ROLES,
            params={},
            path_params={"user_term": user.id},
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_get_roles_with_id_and_role_name(self, mock_client):
        user = UserResource(USER_LIST[0])
        role = RoleResource(ROLE_LIST[0])

        mock_client.get.return_value = ROLE_LIST[0]

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client
        query_params = {"names": role.name}

        response = instance.get_roles(user.id, names=role.name)
        mock_client.get.assert_called_with(
            token=token,
            path=AclClient.USERS_ROLES,
            params=query_params,
            path_params={"user_term": user.id},
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_add_role_with_objects(self, mock_client):
        user = UserResource(USER_LIST[0])
        role = RoleResource(ROLE_LIST[0])

        mock_client.post.return_value = USER_LIST[0]

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.add_role(user, role)

        mock_client.post.assert_called_with(
            token=token,
            body={"role": role.id},
            path=AclClient.USERS_ROLES,
            path_params={"user_term": user.id},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_add_role_with_ids(self, mock_client):
        user = UserResource(USER_LIST[0])
        role = RoleResource(ROLE_LIST[0])

        mock_client.post.return_value = USER_LIST[0]

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.add_role(user.id, role.id)

        mock_client.post.assert_called_with(
            token=token,
            body={"role": role.id},
            path=AclClient.USERS_ROLES,
            path_params={"user_term": user.id},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_add_role_with_terms(self, mock_client):
        user = UserResource(USER_LIST[0])
        role = RoleResource(ROLE_LIST[0])

        mock_client.post.return_value = USER_LIST[0]

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.add_role(user.email, role.name)

        mock_client.post.assert_called_with(
            token=token,
            body={"role": role.name},
            path=AclClient.USERS_ROLES,
            path_params={"user_term": user.email},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_role_with_objects(self, mock_client):
        user = UserResource(USER_LIST[0])
        role = RoleResource(ROLE_LIST[0])

        mock_client.get.return_value = USER_LIST[0]
        mock_client.delete.return_value = True

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.remove_role(user, role)

        mock_client.get.assert_called_with(
            token=token, path=AclClient.USERS_UNIQUE, path_params={"user_term": user.id}
        )

        mock_client.delete.assert_called_with(
            token=token,
            path=AclClient.USERS_ROLES_UNIQUE,
            path_params={"user_term": user.id, "role_id": role.id},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_role_with_ids(self, mock_client):
        user = UserResource(USER_LIST[0])
        role = RoleResource(ROLE_LIST[0])

        mock_client.get.return_value = USER_LIST[0]
        mock_client.delete.return_value = True

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.remove_role(user.id, role.id)

        mock_client.get.assert_called_with(
            token=token, path=AclClient.USERS_UNIQUE, path_params={"user_term": user.id}
        )

        mock_client.delete.assert_called_with(
            token=token,
            path=AclClient.USERS_ROLES_UNIQUE,
            path_params={"user_term": user.id, "role_id": role.id},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_role_with_terms(self, mock_client):
        user = UserResource(USER_LIST[0])
        role = RoleResource(ROLE_LIST[0])

        mock_client.get.return_value = USER_LIST[0]
        mock_client.delete.return_value = True

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.remove_role(user.email, role.id)

        mock_client.get.assert_called_with(
            token=token,
            path=AclClient.USERS_UNIQUE,
            path_params={"user_term": user.email},
        )

        mock_client.delete.assert_called_with(
            token=token,
            path=AclClient.USERS_ROLES_UNIQUE,
            path_params={"user_term": user.email, "role_id": role.id},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_add_permission_with_objects(self, mock_client):
        user = UserResource(USER_LIST[0])
        permission = PermissionResource({"id": 13})
        resource = ResourceResource({"id": 14})
        context = ContextResource({"id": 15})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = USER_LIST[0]
        mock_client.post.return_value = True

        expected_body = {
            "permission": permission.id,
            "resource": resource.id,
            "context": context.id,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.add_permission(
            user,
            permission,
            resource,
            resource_value,
            context=context,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token, path=AclClient.USERS_UNIQUE, path_params={"user_term": user.id}
        )

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.USERS_PERMS,
            path_params={"user_term": user.id},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_add_permission_with_ids(self, mock_client):
        user = UserResource(USER_LIST[0])
        permission = PermissionResource({"id": 13})
        resource = ResourceResource({"id": 14})
        context = ContextResource({"id": 15})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = USER_LIST[0]
        mock_client.post.return_value = True

        expected_body = {
            "permission": permission.id,
            "resource": resource.id,
            "context": context.id,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.add_permission(
            user.id,
            permission.id,
            resource.id,
            resource_value,
            context=context.id,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token, path=AclClient.USERS_UNIQUE, path_params={"user_term": user.id}
        )

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.USERS_PERMS,
            path_params={"user_term": user.id},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_add_permission_with_names(self, mock_client):
        user = UserResource(USER_LIST[0])
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = USER_LIST[0]
        mock_client.post.return_value = True

        expected_body = {
            "permission": permission.name,
            "resource": resource.name,
            "context": context.name,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.add_permission(
            user.email,
            permission.name,
            resource.name,
            resource_value,
            context=context.name,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token,
            path=AclClient.USERS_UNIQUE,
            path_params={"user_term": user.email},
        )

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.USERS_PERMS,
            path_params={"user_term": user.email},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_permission_with_objects(self, mock_client):
        user = UserResource(USER_LIST[0])
        permission = PermissionResource({"id": 13})
        resource = ResourceResource({"id": 14})
        context = ContextResource({"id": 15})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = USER_LIST[0]
        mock_client.delete.return_value = True

        expected_params = {
            "permission": permission.id,
            "resource": resource.id,
            "context": context.id,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.remove_permission(
            user,
            permission,
            resource,
            resource_value,
            context=context,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token, path=AclClient.USERS_UNIQUE, path_params={"user_term": user.id}
        )

        mock_client.delete.assert_called_with(
            token=token,
            params=expected_params,
            path=AclClient.USERS_PERMS,
            path_params={"user_term": user.id},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_permission_with_ids(self, mock_client):
        user = UserResource(USER_LIST[0])
        permission = PermissionResource({"id": 13})
        resource = ResourceResource({"id": 14})
        context = ContextResource({"id": 15})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = USER_LIST[0]
        mock_client.delete.return_value = True

        expected_params = {
            "permission": permission.id,
            "resource": resource.id,
            "context": context.id,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.remove_permission(
            user.id,
            permission.id,
            resource.id,
            resource_value,
            context=context.id,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token, path=AclClient.USERS_UNIQUE, path_params={"user_term": user.id}
        )

        mock_client.delete.assert_called_with(
            token=token,
            params=expected_params,
            path=AclClient.USERS_PERMS,
            path_params={"user_term": user.id},
        )

        self.assertIsInstance(response, UserResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_permission_with_names(self, mock_client):
        user = UserResource(USER_LIST[0])
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = USER_LIST[0]
        mock_client.delete.return_value = True

        expected_params = {
            "permission": permission.name,
            "resource": resource.name,
            "context": context.name,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = User()
        instance.token = token
        instance.client = mock_client

        response = instance.remove_permission(
            user.email,
            permission.name,
            resource.name,
            resource_value,
            context=context.name,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token,
            path=AclClient.USERS_UNIQUE,
            path_params={"user_term": user.email},
        )

        mock_client.delete.assert_called_with(
            token=token,
            params=expected_params,
            path=AclClient.USERS_PERMS,
            path_params={"user_term": user.email},
        )

        self.assertIsInstance(response, UserResource)


class testRole(unittest.TestCase):
    @mock.patch("ingresse_acl.client.AclClient")
    def test_list(self, mock_client):

        mock_client.get.return_value = ROLE_LIST

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.list()

        mock_client.get.assert_called_with(token=token, path=AclClient.ROLES)

        self.assertIsInstance(response, list)
        self.assertEqual(2, len(response))

        for item in response:
            self.assertIsInstance(item, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_get_with_id(self, mock_client):

        mock_client.get.return_value = ROLE_LIST[0]
        term = ROLE_LIST[0].get("id")

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.get(term)

        mock_client.get.assert_called_with(
            token=token, path=AclClient.ROLES_UNIQUE, path_params={"role_term": term}
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_get_with_name(self, mock_client):

        mock_client.get.return_value = ROLE_LIST[0]
        term = ROLE_LIST[0].get("name")

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.get(term)

        mock_client.get.assert_called_with(
            token=token, path=AclClient.ROLES_UNIQUE, path_params={"role_term": term}
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_create(self, mock_client):

        mock_client.post.return_value = ROLE_LIST[0]
        name = ROLE_LIST[0].get("name")
        alias = ROLE_LIST[0].get("alias")
        desc = ROLE_LIST[0].get("description")

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.create(name, alias, desc)

        mock_client.post.assert_called_with(
            token=token,
            body={"name": name, "alias": alias, "description": desc},
            path=AclClient.ROLES,
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_update_with_object(self, mock_client):

        role = RoleResource(ROLE_LIST[0])

        mock_client.put.return_value = True

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.update(role)

        mock_client.put.assert_called_with(
            token=token,
            body={"alias": role.alias, "description": role.description},
            path=AclClient.ROLES_UNIQUE,
            path_params={"role_term": role.id},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_update_with_id(self, mock_client):

        role = RoleResource(ROLE_LIST[0])

        mock_client.put.return_value = True

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.update(
            role.id, alias=role.alias, description=role.description
        )

        mock_client.put.assert_called_with(
            token=token,
            body={"alias": role.alias, "description": role.description},
            path=AclClient.ROLES_UNIQUE,
            path_params={"role_term": role.id},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_update_with_name(self, mock_client):

        role = RoleResource(ROLE_LIST[0])

        mock_client.put.return_value = True

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.update(
            role.name, alias=role.alias, description=role.description
        )

        mock_client.put.assert_called_with(
            token=token,
            body={"alias": role.alias, "description": role.description},
            path=AclClient.ROLES_UNIQUE,
            path_params={"role_term": role.name},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_with_object(self, mock_client):

        role = RoleResource(ROLE_LIST[0])

        mock_client.delete.return_value = True

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.remove(role)

        mock_client.delete.assert_called_with(
            token=token, path=AclClient.ROLES_UNIQUE, path_params={"role_term": role.id}
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_with_id(self, mock_client):

        role = RoleResource(ROLE_LIST[0])

        mock_client.delete.return_value = True

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.remove(role.id)

        mock_client.delete.assert_called_with(
            token=token, path=AclClient.ROLES_UNIQUE, path_params={"role_term": role.id}
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_with_name(self, mock_client):

        role = RoleResource(ROLE_LIST[0])

        mock_client.delete.return_value = True

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.remove(role.name)

        mock_client.delete.assert_called_with(
            token=token,
            path=AclClient.ROLES_UNIQUE,
            path_params={"role_term": role.name},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_add_permission_with_objects(self, mock_client):
        role = RoleResource(ROLE_LIST[0])
        permission = PermissionResource({"id": 13})
        resource = ResourceResource({"id": 14})
        context = ContextResource({"id": 15})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = ROLE_LIST[0]
        mock_client.post.return_value = True

        expected_body = {
            "permission": permission.id,
            "resource": resource.id,
            "context": context.id,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.add_permission(
            role,
            permission,
            resource,
            resource_value,
            context=context,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token, path=AclClient.ROLES_UNIQUE, path_params={"role_term": role.id}
        )

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.ROLES_PERMS,
            path_params={"role_term": role.id},
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_add_permission_with_ids(self, mock_client):
        role = RoleResource(ROLE_LIST[0])
        permission = PermissionResource({"id": 13})
        resource = ResourceResource({"id": 14})
        context = ContextResource({"id": 15})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = ROLE_LIST[0]
        mock_client.post.return_value = True

        expected_body = {
            "permission": permission.id,
            "resource": resource.id,
            "context": context.id,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.add_permission(
            role.id,
            permission.id,
            resource.id,
            resource_value,
            context=context.id,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token, path=AclClient.ROLES_UNIQUE, path_params={"role_term": role.id}
        )

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.ROLES_PERMS,
            path_params={"role_term": role.id},
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_add_permission_with_names(self, mock_client):
        role = RoleResource(ROLE_LIST[0])
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = ROLE_LIST[0]
        mock_client.post.return_value = True

        expected_body = {
            "permission": permission.name,
            "resource": resource.name,
            "context": context.name,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.add_permission(
            role.name,
            permission.name,
            resource.name,
            resource_value,
            context=context.name,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token,
            path=AclClient.ROLES_UNIQUE,
            path_params={"role_term": role.name},
        )

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.ROLES_PERMS,
            path_params={"role_term": role.name},
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_permission_with_objects(self, mock_client):
        role = RoleResource(ROLE_LIST[0])
        permission = PermissionResource({"id": 13})
        resource = ResourceResource({"id": 14})
        context = ContextResource({"id": 15})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = ROLE_LIST[0]
        mock_client.delete.return_value = True

        expected_params = {
            "permission": permission.id,
            "resource": resource.id,
            "context": context.id,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.remove_permission(
            role,
            permission,
            resource,
            resource_value,
            context=context,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token, path=AclClient.ROLES_UNIQUE, path_params={"role_term": role.id}
        )

        mock_client.delete.assert_called_with(
            token=token,
            params=expected_params,
            path=AclClient.ROLES_PERMS,
            path_params={"role_term": role.id},
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_permission_with_ids(self, mock_client):
        role = RoleResource(ROLE_LIST[0])
        permission = PermissionResource({"id": 13})
        resource = ResourceResource({"id": 14})
        context = ContextResource({"id": 15})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = ROLE_LIST[0]
        mock_client.delete.return_value = True

        expected_params = {
            "permission": permission.id,
            "resource": resource.id,
            "context": context.id,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.remove_permission(
            role.id,
            permission.id,
            resource.id,
            resource_value,
            context=context.id,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token, path=AclClient.ROLES_UNIQUE, path_params={"role_term": role.id}
        )

        mock_client.delete.assert_called_with(
            token=token,
            params=expected_params,
            path=AclClient.ROLES_PERMS,
            path_params={"role_term": role.id},
        )

        self.assertIsInstance(response, RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_remove_permission_with_names(self, mock_client):
        role = RoleResource(ROLE_LIST[0])
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        mock_client.get.return_value = ROLE_LIST[0]
        mock_client.delete.return_value = True

        expected_params = {
            "permission": permission.name,
            "resource": resource.name,
            "context": context.name,
            "resourceValue": resource_value,
            "contextValue": context_value,
        }

        token = "MyToken"
        instance = Role()
        instance.token = token
        instance.client = mock_client

        response = instance.remove_permission(
            role.name,
            permission.name,
            resource.name,
            resource_value,
            context=context.name,
            context_value=context_value,
        )

        mock_client.get.assert_called_with(
            token=token,
            path=AclClient.ROLES_UNIQUE,
            path_params={"role_term": role.name},
        )

        mock_client.delete.assert_called_with(
            token=token,
            params=expected_params,
            path=AclClient.ROLES_PERMS,
            path_params={"role_term": role.name},
        )

        self.assertIsInstance(response, RoleResource)


class testBatchUser(unittest.TestCase):
    @mock.patch("ingresse_acl.client.AclClient")
    def test_execute_with_objects(self, mock_client):
        user = UserResource(USER_LIST[0])
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        mock_client.post.return_value = True

        expected_body = [
            {
                "permission": permission.id,
                "resource": resource.id,
                "context": context.id,
                "resourceValue": resource_value,
                "contextValue": context_value,
            }
        ]

        token = "MyToken"
        instance = BatchUser()
        instance.token = token
        instance.client = mock_client

        instance.set_user(user)
        instance.add_permission(
            permission,
            resource,
            resource_value,
            context=context,
            context_value=context_value,
        )
        response = instance.execute()

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.BATCH_USERS_PERM,
            path_params={"user_term": user.id},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_execute_with_ids(self, mock_client):
        user = UserResource(USER_LIST[0])
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        mock_client.post.return_value = True

        expected_body = [
            {
                "permission": permission.id,
                "resource": resource.id,
                "context": context.id,
                "resourceValue": resource_value,
                "contextValue": context_value,
            }
        ]

        token = "MyToken"
        instance = BatchUser()
        instance.token = token
        instance.client = mock_client

        instance.set_user(user.id)
        instance.add_permission(
            permission.id,
            resource.id,
            resource_value,
            context=context.id,
            context_value=context_value,
        )
        response = instance.execute()

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.BATCH_USERS_PERM,
            path_params={"user_term": user.id},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_execute_with_terms(self, mock_client):
        user = UserResource(USER_LIST[0])
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        mock_client.post.return_value = True

        expected_body = [
            {
                "permission": permission.name,
                "resource": resource.name,
                "context": context.name,
                "resourceValue": resource_value,
                "contextValue": context_value,
            }
        ]

        token = "MyToken"
        instance = BatchUser()
        instance.token = token
        instance.client = mock_client

        instance.set_user(user.email)
        instance.add_permission(
            permission.name,
            resource.name,
            resource_value,
            context=context.name,
            context_value=context_value,
        )
        response = instance.execute()

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.BATCH_USERS_PERM,
            path_params={"user_term": user.email},
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_execute_fail(self, mock_client):
        token = "MyToken"
        instance = BatchUser()
        instance.token = token
        instance.client = mock_client

        with self.assertRaises(Exception) as context:
            instance.execute()

        self.assertEquals("User must be setted", context.exception.message)


class testBatchRole(unittest.TestCase):
    @mock.patch("ingresse_acl.client.AclClient")
    def test_execute_permission_with_objects(self, mock_client):
        role = RoleResource(ROLE_LIST[0])
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        mock_client.post.return_value = True

        expected_body = [
            {
                "permission": permission.id,
                "resource": resource.id,
                "context": context.id,
                "resourceValue": resource_value,
                "contextValue": context_value,
            }
        ]

        token = "MyToken"
        instance = BatchRole()
        instance.token = token
        instance.client = mock_client

        instance.set_role(role)
        instance.add_permission(
            permission,
            resource,
            resource_value,
            context=context,
            context_value=context_value,
        )
        response = instance.execute()

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.BATCH_ROLES_PERM,
            path_params={"role_term": role.id},
        )

        self.assertEqual([], response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_execute_permission_with_ids(self, mock_client):
        role = RoleResource(ROLE_LIST[0])
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        mock_client.post.return_value = True

        expected_body = [
            {
                "permission": permission.id,
                "resource": resource.id,
                "context": context.id,
                "resourceValue": resource_value,
                "contextValue": context_value,
            }
        ]

        token = "MyToken"
        instance = BatchRole()
        instance.token = token
        instance.client = mock_client

        instance.set_role(role.id)
        instance.add_permission(
            permission.id,
            resource.id,
            resource_value,
            context=context.id,
            context_value=context_value,
        )
        response = instance.execute()

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.BATCH_ROLES_PERM,
            path_params={"role_term": role.id},
        )

        self.assertEqual([], response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_execute_permission_with_names(self, mock_client):
        role = RoleResource(ROLE_LIST[0])
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        mock_client.post.return_value = True

        expected_body = [
            {
                "permission": permission.name,
                "resource": resource.name,
                "context": context.name,
                "resourceValue": resource_value,
                "contextValue": context_value,
            }
        ]

        token = "MyToken"
        instance = BatchRole()
        instance.token = token
        instance.client = mock_client

        instance.set_role(role.name)
        instance.add_permission(
            permission.name,
            resource.name,
            resource_value,
            context=context.name,
            context_value=context_value,
        )
        response = instance.execute()

        mock_client.post.assert_called_with(
            token=token,
            body=expected_body,
            path=AclClient.BATCH_ROLES_PERM,
            path_params={"role_term": role.name},
        )

        self.assertEqual([], response)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_execute_roles(self, mock_client):
        role = RoleResource(ROLE_LIST[0])

        mock_client.post.return_value = [ROLE_LIST[0]]

        expected_body = [
            {
                "name": role.name,
                "alias": role.alias,
                "description": role.description,
                "system": False,
            }
        ]

        token = "MyToken"
        instance = BatchRole()
        instance.token = token
        instance.client = mock_client

        instance.add_role(role.name, role.alias, role.description)
        response = instance.execute()

        mock_client.post.assert_called_with(
            token=token, body=expected_body, path=AclClient.BATCH_ROLES
        )

        self.assertIsInstance(response, list)
        self.assertEqual(1, len(response))
        self.assertIsInstance(response[0], RoleResource)

    @mock.patch("ingresse_acl.client.AclClient")
    def test_execute_fail(self, mock_client):
        permission = PermissionResource({"id": 13, "name": "perm-name"})
        resource = ResourceResource({"id": 14, "name": "res-name"})
        context = ContextResource({"id": 15, "name": "ctx-name"})

        resource_value = "rval"
        context_value = "cval"

        token = "MyToken"
        instance = BatchRole()
        instance.token = token
        instance.client = mock_client

        instance.add_permission(
            permission,
            resource,
            resource_value,
            context=context,
            context_value=context_value,
        )

        with self.assertRaises(Exception) as context:
            instance.execute()

        self.assertEquals("Role must be setted", context.exception.message)


USER_LIST = [
    {
        "id": 12,
        "ingresseId": 21,
        "email": "user21@ing.com",
        "permissions": [],
        "roles": [],
    },
    {
        "id": 13,
        "ingresseId": 31,
        "email": "user31@ing.com",
        "permissions": [],
        "roles": [],
    },
]

ROLE_LIST = [
    {
        "id": 14,
        "name": "role-14",
        "alias": "role",
        "description": "role desc",
        "permissions": [],
    },
    {
        "id": 15,
        "name": "role-15",
        "alias": "role",
        "description": "role desc",
        "permissions": [],
    },
]
