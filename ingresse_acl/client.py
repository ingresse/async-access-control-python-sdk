from ingresse_acl.sdk import VERSION

import requests
import json

HOST = "https://acl.ingresse.com"

class AclError(object):
    #Authorization
    ACCESS_DENIED = 1000

    #Database
    PERMISSION_NOT_FOUND              = 5000
    PERMISSION_UNABLE_REMOVAL         = 5001
    ROLE_NOT_FOUND                    = 5004
    ROLE_UNABLE_REMOVAL               = 5005
    ROLE_SYSTEM_DENIED_REMOVAL        = 5006
    RESOURCE_NOT_FOUND                = 5007
    RESOURCE_UNABLE_REMOVAL           = 5008
    USER_NOT_FOUND                    = 5009
    USER_UNABLE_REMOVAL               = 5010
    ROLE_SYSTEM_FLAGGED_DENIED_UPDATE = 5011
    PERMISSION_INTEGRITY_ERROR        = 5013
    RESOURCE_INTEGRITY_ERROR          = 5014
    ROLE_INTEGRITY_ERROR              = 5015
    USER_INTEGRITY_ERROR              = 5016
    DATA_TO_LONG_ERROR                = 5017
    USER_UNABLE_TO_ASSOCIATE_ROLE     = 5018
    USER_UNABLE_TO_DISASSOCIATE_ROLE  = 5019
    USER_ROLE_NOT_FOUND               = 5020
    ROLE_UNABLE_TO_ASSOCIATE_PERM     = 5021
    ROLE_UNABLE_TO_DISASSOCIATE_PERM  = 5022
    CONTEXT_NOT_FOUND                 = 5023
    CONTEXT_UNABLE_REMOVAL            = 5024
    CONTEXT_INTEGRITY_ERROR           = 5025

    #Usage
    ALL_PARAMETERS_REQUIRED       = 4000
    PERMISSION_ID_REQUIRED        = 4001
    PERMISSION_ID_INTEGER         = 4002
    RESOURCE_VALUE_REQUIRED       = 4003
    ROLE_ID_REQUIRED              = 4005
    ROLE_ID_INTEGER               = 4006
    RESOURCE_ID_REQUIRED          = 4007
    RESOURCE_ID_INTEGER           = 4008
    EMAIL_REQUIRED                = 4009
    INGRESSE_ID_INTEGER           = 4010
    USER_ID_REQUIRED              = 4011
    USER_ID_INTEGER               = 4012
    PERMISSIONS_ARRAY             = 4013
    RESOURCE_NAME_REQUIRED        = 4014
    PERMISSION_NAME_REQUIRED      = 4015
    INGRESSE_ID_REQUIRED          = 4016
    PERMISSIONS_OBJECTS_MALFORMED = 4017
    CONTEXT_ID_REQUIRED           = 4018
    CONTEXT_ID_INTEGER            = 4019
    JSON_REQUEST_TYPE             = 4020
    RESOURCES_OBJECTS_MALFORMED   = 4021
    CONTEXTS_OBJECTS_MALFORMED    = 4022
    SYSTEM_BOOLEAN                = 4023
    ROLES_OBJECTS_MALFORMED       = 4024
    CONTEXT_REQUIRED              = 4025
    RESOURCE_REQUIRED             = 4026
    PERMISSION_REQUIRED           = 4027
    ROLE_REQUIRED                 = 4028
    SYSTEM_REQUIRED               = 4029


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

    VALIDATE = "validate"

    ROLES        = "roles"
    ROLES_UNIQUE = "roles/{role_term}"
    ROLES_PERMS  = "roles/{role_term}/permissions"
    ROLES_USERS  = "roles/{role_id}/users"

    BATCH_USERS_PERM  = "batch/users/{user_term}/permissions"
    BATCH_ROLES       = "batch/roles"
    BATCH_ROLES_PERM  = "batch/roles/{role_term}/permissions"

    def __init__(self, host=None):
        """Initiates instance

        Keyword Arguments:
        environment -- string
        """
        if not host:
            host = HOST

        if not "http" in host:
            host = "http://{}".format(host)

        if host[-1] == "/":
            host = host[0:-1]

        self.host = host

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
