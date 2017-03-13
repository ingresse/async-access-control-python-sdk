from sdk import VERSION

import requests
import json

ENVIRONMENT = {
    "production":   "http://private.ip",
    "homologation": "http://private.ip",
    "local":        "http://acl.ingresse.dev"
}

class AclException(Exception):
    error_code = "0000"
    def __init__(self, resp):
        """Initiates instance"""
        data = None
        try:
            data = resp.json()
        except:
            pass

        self.error_code = "0000" if data is None else data.get("code")

        message = "[{status_code}/{error_code}] - {msg}".format(
            status_code=resp.status_code,
            error_code=self.error_code,
            msg="Unknow Error" if data is None else data.get("message")
        )
        super(AclException, self).__init__(message)


class AclClient(object):
    USERS              = "users"
    USERS_UNIQUE       = "users/{user_term}"
    USERS_ROLES        = "users/{user_term}/roles"
    USERS_ROLES_UNIQUE = "users/{user_term}/roles/{role_id}"
    USERS_PERMS        = "users/{user_term}/permissions"

    ROLES        = "roles"
    ROLES_UNIQUE = "roles/{role_term}"
    ROLES_PERMS  = "roles/{role_term}/permissions"

    BATCH_USERS_PERM  = "batch/users/{user_term}/permissions"
    BATCH_ROLES       = "batch/roles"
    BATCH_ROLES_PERM  = "batch/roles/{role_term}/permissions"

    def __init__(self, environment):
        """Initiates instance

        Keyword Arguments:
        environment -- string
        """
        self.host = ENVIRONMENT.get(environment, ENVIRONMENT.get("production"))

    def get(self, token, path, path_params={}, params={}):
        """Performs a GET request

        Keyword Arguments:
        token       -- string
        path        -- string
        path_params -- dict
        params      -- dict

        Returns: mixed
        """
        url     = self.__get_url(path, path_params)
        headers = self.__get_header(token, 'get')
        response = requests.get(url, headers=headers, params=params)
        self.__validate_response(response)
        return response.json().get('data', {})

    def post(self, token, path, path_params={}, body={}):
        """Performs a POST request

        Keyword Arguments:
        token       -- string
        path        -- string
        path_params -- dict
        body        -- dict

        Returns: mixed
        """
        url     = self.__get_url(path, path_params)
        headers = self.__get_header(token, 'post')
        response = requests.post(url, headers=headers, data=json.dumps(body))
        self.__validate_response(response)
        return response.json().get('data', {})

    def put(self, token, path, path_params={}, body={}):
        """Performs a PUT request

        Keyword Arguments:
        token       -- string
        path        -- string
        path_params -- dict
        body        -- dict

        Returns: boolean
        """
        url     = self.__get_url(path, path_params)
        headers = self.__get_header(token, 'put')
        response = requests.put(url, headers=headers, data=json.dumps(body))
        self.__validate_response(response)
        return True

    def delete(self, token, path, path_params={}, params={}):
        """Performs a DELETE request

        Keyword Arguments:
        token       -- string
        path        -- string
        path_params -- dict
        params      -- dict

        Returns: boolean
        """
        url     = self.__get_url(path, path_params)
        headers = self.__get_header(token, 'delete')
        response = requests.delete(url, headers=headers, params=params)
        self.__validate_response(response)
        return True

    def __validate_response(self, response):
        """Validates the response

        Keyword Arguments:
        response -- requests.Response

        Raises:
        - AclException
        """
        if response.status_code not in [200, 204]:
            raise AclException(response)

    def __get_url(self, path, params):
        """Get the URL

        Keyword Arguments:
        path   -- string
        params -- dict

        Returns: string
        """
        return "{}/{}".format(self.host, path.format(**params))

    def __get_header(self, token, method):
        """Get the Header

        Keyword Arguments:
        token  -- string
        method -- string

        Returns: dict
        """
        header = {
            "Authorization": "Bearer {}".format(token),
            "User-Agent":    "ingresse-acl-python-sdk/{}".format(VERSION),
        }

        if method in ['post', 'put']:
            header.update({"Content-Type": "application/json"})

        return header
