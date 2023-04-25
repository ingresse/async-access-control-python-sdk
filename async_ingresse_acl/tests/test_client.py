import json
import unittest

import mock

from async_ingresse_acl.client import *



class testAclException(unittest.TestCase):
    def test_instance(self):
        resp = ResponseClone(500, {"code": "0001", "message": "message test"})

        expt = AclException(resp)

        self.assertEqual("[500/0001] - message test", expt.message)

    def test_instance_no_message(self):
        resp = ResponseClone(500, None)

        expt = AclException(resp)

        self.assertEqual("[500/0000] - Unknow Error", expt.message)


class testAclClient(unittest.TestCase):
    @mock.patch("ingresse_acl.client.requests")
    def test_get(self, mock_requests):
        token = "my-token"
        path = "users/{term}"
        params = {"id": 1}
        path_params = {"term": "user1"}

        mock_requests.get.return_value = ResponseClone(200, {"data": True})

        client = AclClient("local")
        response = client.get(token, path, path_params=path_params, params=params)

        expected_url = "http://acl.ingresse.dev/users/user1"
        expected_header = {
            "Authorization": "Bearer {}".format(token),
            "User-Agent": "ingresse-acl-python-sdk/{}".format(VERSION),
        }

        mock_requests.get.assert_called_with(
            expected_url, headers=expected_header, params=params
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.requests")
    def test_post(self, mock_requests):
        token = "my-token"
        path = "users/{term}"
        body = {"id": 1}
        path_params = {"term": "user1"}

        mock_requests.post.return_value = ResponseClone(200, {"data": True})

        client = AclClient("local")
        response = client.post(token, path, path_params=path_params, body=body)

        expected_url = "http://acl.ingresse.dev/users/user1"
        expected_header = {
            "Authorization": "Bearer {}".format(token),
            "User-Agent": "ingresse-acl-python-sdk/{}".format(VERSION),
            "Content-Type": "application/json",
        }

        mock_requests.post.assert_called_with(
            expected_url, headers=expected_header, data=json.dumps(body)
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.requests")
    def test_put(self, mock_requests):
        token = "my-token"
        path = "users/{term}"
        body = {"id": 1}
        path_params = {"term": "user1"}

        mock_requests.put.return_value = ResponseClone(200, {"data": True})

        client = AclClient("local")
        response = client.put(token, path, path_params=path_params, body=body)

        expected_url = "http://acl.ingresse.dev/users/user1"
        expected_header = {
            "Authorization": "Bearer {}".format(token),
            "User-Agent": "ingresse-acl-python-sdk/{}".format(VERSION),
            "Content-Type": "application/json",
        }

        mock_requests.put.assert_called_with(
            expected_url, headers=expected_header, data=json.dumps(body)
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.requests")
    def test_delete(self, mock_requests):
        token = "my-token"
        path = "users/{term}"
        params = {"id": 1}
        path_params = {"term": "user1"}

        mock_requests.delete.return_value = ResponseClone(200, {"data": True})

        client = AclClient("local")
        response = client.delete(token, path, path_params=path_params, params=params)

        expected_url = "http://acl.ingresse.dev/users/user1"
        expected_header = {
            "Authorization": "Bearer {}".format(token),
            "User-Agent": "ingresse-acl-python-sdk/{}".format(VERSION),
        }

        mock_requests.delete.assert_called_with(
            expected_url, headers=expected_header, params=params
        )

        self.assertTrue(response)

    @mock.patch("ingresse_acl.client.requests")
    def test_fail(self, mock_requests):
        token = "my-token"
        path = "users/{term}"
        params = {"id": 1}
        path_params = {"term": "user1"}

        mock_requests.get.return_value = ResponseClone(
            500, {"code": "0001", "message": "message test"}
        )

        client = AclClient("local")

        expected_url = "http://acl.ingresse.dev/users/user1"
        expected_header = {
            "Authorization": "Bearer {}".format(token),
            "User-Agent": "ingresse-acl-python-sdk/{}".format(VERSION),
        }

        with self.assertRaises(AclException) as context:
            response = client.get(token, path, path_params=path_params, params=params)

        mock_requests.get.assert_called_with(
            expected_url, headers=expected_header, params=params
        )

        self.assertEqual("[500/0001] - message test", context.exception.message)


class ResponseClone:
    status_code = None
    resp = None

    def __init__(self, status_code, resp):
        self.status_code = status_code
        self.resp = resp

    def json(self):
        if not self.resp:
            raise Exception()
        return self.resp
