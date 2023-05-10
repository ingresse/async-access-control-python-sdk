# Access Control Python SDK

## Install

```
pip install git+https://github.com/ingresse/async-access-control-python-sdk.git@@{version}#egg=ingresse_acl
```

Replace `{version}` for the Release Version you want

## Usage

Instanciate the *IngresseACL* object with your token (JWT).

```python
from ingresse_acl import IngresseACL

acl = IngresseACL("my-token")
```

### Users

#### Create

```python
new_user = acl.User.create(ingresse_id=1234, email="user1234@ing.com")
```

or just

```python
new_user = acl.User.create(1234, "user1234@ing.com")
```

#### Get

You can get a User passing the user Id (ACL user Id) or the user Email

```python
my_user = acl.User.get(123)
```

or

```python
my_user = acl.User.get("user4322@ing.com")
```

#### Update

```python
acl.User.update(123, email="new_email@ing.com")
```

or

```python
acl.User.update("old_email@ing.com", email="new_email@ing.com")
```

or

```python
my_user = acl.User.get(123)
my_user.email = "new_email@ing.com"
acl.User.update(my_user)
```

#### Remove

```python
acl.User.remove(1432)
```

or

```python
my_user = acl.User.get(1432)
acl.User.remove(my_user)
```

#### Associate/Remove Role

To associate:

```python
### User ACL Id: 2132 and Role Id 8756
acl.User.add_role(2132, role=8756)
```

or

```python
### User ACL Id: 2132 and Role Id 8756
my_user = acl.User.get(2132)
my_role = acl.Role.get(8756)
acl.User.add_role(my_user, role=my_role)
```

To remove:

```python
### User ACL Id: 2132 and Role Id 8756
acl.User.remove_role(2132, role=8756)
```

or

```python
### User ACL Id: 2132 and Role Id 8756
my_user = acl.User.get(2132)
my_role = acl.Role.get(8756)
acl.User.remove_role(my_user, role=my_role)
```

#### Associate/Remove Permission
To associate:

```python
### User ACL Id: 2132, Permission Id: 8756, Resource Id: 6543,
### Context Id: 4624
my_user = acl.User.add_permission(2132, 8756, 6543, "resVal", context=4624, context_value="ctxVal")
```

or

```python
### User ACL Id: 2132, Permission Name: "can-read"
### Resource Name: "planner", Context Name: "event"
my_user = acl.User.add_permission(2132, "can-read", "planner", "resVal", context="event", context_value="ctxVal")
```

or

```python
### User ACL Id: 2132, Permission Name: "can-read"
### Resource Name: "planner", Context Name: "event"
my_user = acl.User.get(2132)
my_user = acl.User.add_permission(my_user, "can-read", "planner", "resVal", context="event", context_value="ctxVal")
```

To remove:

```python
### User ACL Id: 2132, Permission Id: 8756, Resource Id: 6543,
### Context Id: 4624
my_user = acl.User.remove_permission(2132, 8756, 6543, "resVal", context=4624, context_value="ctxVal")
```

or

```python
### User ACL Id: 2132, Permission Name: "can-read"
### Resource Name: "planner", Context Name: "event"
my_user = acl.User.remove_permission(2132, "can-read", "planner", "resVal", context="event", context_value="ctxVal")
```

or

```python
### User ACL Id: 2132, Permission Name: "can-read"
### Resource Name: "planner", Context Name: "event"
my_user = acl.User.get(2132)
my_user = acl.User.remove_permission(my_user, "can-read", "planner", "resVal", context="event", context_value="ctxVal")
```

### Roles

#### Create

```python
new_user = acl.Role.create(name="my-role", alias="My Role", description="My Role for teste")
```

or just

```python
new_user = acl.Role.create("my-role", "My Role", "My Role for teste")
```

#### Get
You can get a Role passing the Role Id or the Role Name

```python
my_user = acl.Role.get(123)
```

or

```python
my_user = acl.Role.get("my-role")
```

#### Update

```python
acl.Role.update(123, alias="New alias", description="New Description")
```

or

```python
acl.Role.update("my-role", alias="New alias", description="New Description")
```

or

```python
my_role = acl.Role.get("my-role")
my_role.alias = "New alias"
my_role.description = "New Description"
acl.Role.update(my_role)
```

#### Remove

```python
acl.Role.remove(1432)
```

or

```python
my_role = acl.Role.get(1432)
acl.Role.remove(my_role)
```

#### Associate/Remove Permission
To associate:

```python
### Role Id: 2132, Permission Id: 8756, Resource Id: 6543,
### Context Id: 4624
my_role = acl.Role.add_permission(2132, 8756, 6543, "resVal", context=4624, context_value="ctxVal")
```

or

```python
### Role Name: "my-role", Permission Name: "can-read"
### Resource Name: "planner", Context Name: "event"
my_role = acl.Role.add_permission("my-role", "can-read", "planner", "resVal", context="event", context_value="ctxVal")
```

or

```python
### Role Id: 2132, Permission Name: "can-read"
### Resource Name: "planner", Context Name: "event"
my_role = acl.Role.get(2132)
my_role = acl.Role.add_permission(my_role, "can-read", "planner", "resVal", context="event", context_value="ctxVal")
```

To remove:

```python
### Role Id: 2132, Permission Id: 8756, Resource Id: 6543,
### Context Id: 4624
my_role = acl.Role.remove_permission(2132, 8756, 6543, "resVal", context=4624, context_value="ctxVal")
```

or

```python
### User ACL Id: 2132, Permission Name: "can-read"
### Resource Name: "planner", Context Name: "event"
my_role = acl.Role.remove_permission(2132, "can-read", "planner", "resVal", context="event", context_value="ctxVal")
```

or

```python
### User ACL Id: 2132, Permission Name: "can-read"
### Resource Name: "planner", Context Name: "event"
my_role = acl.Role.get(2132)
my_role = acl.Role.remove_permission(my_role, "can-read", "planner", "resVal", context="event", context_value="ctxVal")
```

