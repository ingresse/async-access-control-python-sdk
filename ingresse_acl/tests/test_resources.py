import unittest

from ingresse_acl.resources import *

class testSdkResource(unittest.TestCase):

    def test_get_dict(self):
        expected = None

        item = SdkResource()

        self.assertEqual(expected, item.get_dict())

class testUser(unittest.TestCase):

    def test_get_dict(self):
        expected = {"id": 1, "email": "user1@ing.com", "ingresseId": 1}

        item = User(expected)

        self.assertItemsEqual(expected, item.get_dict())

class testRole(unittest.TestCase):

    def test_get_dict(self):
        expected = {
            "id": 1,
            "name": "name-1",
            "alias": "alias 1",
            "description": "desc 1",
            "system": True
        }

        item = Role(expected)

        self.assertItemsEqual(expected, item.get_dict())

class testPermission(unittest.TestCase):

    def test_get_dict(self):
        expected = {
            "id": 1,
            "name": "name-1",
            "alias": "alias 1",
            "description": "desc 1"
        }

        item = Permission(expected)

        self.assertItemsEqual(expected, item.get_dict())

class testResource(unittest.TestCase):

    def test_get_dict(self):
        expected = {
            "id": 1,
            "name": "name-1",
            "alias": "alias 1",
            "description": "desc 1"
        }

        item = Resource(expected)

        self.assertItemsEqual(expected, item.get_dict())

class testContext(unittest.TestCase):

    def test_get_dict(self):
        expected = {
            "id": 1,
            "name": "name-1",
            "alias": "alias 1",
            "description": "desc 1"
        }

        item = Context(expected)

        self.assertItemsEqual(expected, item.get_dict())

class testRolePermission(unittest.TestCase):

    def test_get_dict(self):
        perm = {
            "permission": "perm",
            "resourceName": "res-1",
            "contextName": "ctx-1",
            "resourceValue": "val1",
            "contextValue": "val2"
        }

        item = RolePermission(perm)

        expected = {
            "permission": "perm",
            "resource": "res-1",
            "resourceValue": "val1",
            "context": "ctx-1",
            "contextValue": "val2"
        }

        self.assertItemsEqual(expected, item.get_dict())

class testUserPermission(unittest.TestCase):

    def test_get_dict(self):
        perm = {
            "permission": "perm",
            "resourceName": "res-1",
            "contextName": "ctx-1",
            "resourceValue": "val1",
            "contextValue": "val2"
        }

        item = UserPermission(perm)

        expected = {
            "permission": "perm",
            "resource": "res-1",
            "resourceValue": "val1",
            "context": "ctx-1",
            "contextValue": "val2"
        }

        self.assertItemsEqual(expected, item.get_dict())
