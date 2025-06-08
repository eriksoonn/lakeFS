from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uuid

app = FastAPI(title="lakeFS ACL Auth Server")

# In-memory storage
USERS = {}
GROUPS = {}
POLICIES = {}
CREDENTIALS = {}


class Pagination(BaseModel):
    next_offset: Optional[str] = None
    results: int
    has_more: bool


class User(BaseModel):
    username: str
    creation_date: int
    friendly_name: Optional[str] = None
    email: Optional[str] = None
    source: Optional[str] = None


class UserCreation(BaseModel):
    username: str
    email: Optional[str] = None
    friendly_name: Optional[str] = None
    source: Optional[str] = None
    external_id: Optional[str] = None
    invite: Optional[bool] = False


class UserList(BaseModel):
    pagination: Pagination
    results: List[User]


class Credentials(BaseModel):
    access_key_id: str
    creation_date: int


class CredentialsWithSecret(Credentials):
    secret_access_key: str
    user_name: str


class CredentialsList(BaseModel):
    pagination: Pagination
    results: List[Credentials]


class Group(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    creation_date: int


class GroupCreation(BaseModel):
    id: str
    description: Optional[str] = None


class GroupList(BaseModel):
    pagination: Pagination
    results: List[Group]


class Policy(BaseModel):
    name: str
    creation_date: int
    acl: Optional[str] = None


class PolicyList(BaseModel):
    pagination: Pagination
    results: List[Policy]


# Utility functions


def now_ts() -> int:
    return int(datetime.utcnow().timestamp())


# Users endpoints
@app.get("/auth/users", response_model=UserList)
def list_users(
    prefix: Optional[str] = None, after: Optional[str] = None, amount: int = 1000
):
    names = sorted([n for n in USERS if (not prefix or n.startswith(prefix))])
    if after:
        names = [n for n in names if n > after]
    selected = names[:amount]
    has_more = len(names) > amount
    next_offset = selected[-1] if has_more else None
    return UserList(
        pagination=Pagination(
            next_offset=next_offset, results=len(selected), has_more=has_more
        ),
        results=[USERS[n] for n in selected],
    )


@app.post("/auth/users", response_model=User, status_code=201)
def create_user(user: UserCreation):
    if user.username in USERS:
        raise HTTPException(status_code=409, detail="user exists")
    u = User(
        username=user.username,
        creation_date=now_ts(),
        friendly_name=user.friendly_name,
        email=user.email,
        source=user.source,
    )
    USERS[user.username] = u
    return u


@app.get("/auth/users/{user_id}", response_model=User)
def get_user(user_id: str):
    u = USERS.get(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="not found")
    return u


@app.delete("/auth/users/{user_id}", status_code=204)
def delete_user(user_id: str):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    USERS.pop(user_id)
    # remove credentials
    for key in list(CREDENTIALS):
        if CREDENTIALS[key].user_name == user_id:
            CREDENTIALS.pop(key)
    # remove from groups
    for g in GROUPS.values():
        if user_id in g.get("members", []):
            g["members"].remove(user_id)
    return None


@app.get("/auth/users/{user_id}/groups", response_model=GroupList)
def list_user_groups(
    user_id: str,
    prefix: Optional[str] = None,
    after: Optional[str] = None,
    amount: int = 1000,
):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    user_groups = [
        g_id for g_id, g in GROUPS.items() if user_id in g.get("members", [])
    ]
    names = sorted([n for n in user_groups if (not prefix or n.startswith(prefix))])
    if after:
        names = [n for n in names if n > after]
    selected = names[:amount]
    has_more = len(names) > amount
    next_offset = selected[-1] if has_more else None
    return GroupList(
        pagination=Pagination(
            next_offset=next_offset, results=len(selected), has_more=has_more
        ),
        results=[
            Group(
                id=n,
                name=n,
                description=GROUPS[n]["description"],
                creation_date=GROUPS[n]["creation_date"],
            )
            for n in selected
        ],
    )


@app.get("/auth/users/{user_id}/policies", response_model=PolicyList)
def list_user_policies(
    user_id: str,
    prefix: Optional[str] = None,
    after: Optional[str] = None,
    amount: int = 1000,
    effective: Optional[bool] = False,
):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    direct = (
        USERS[user_id].dict().get("policies", [])
        if hasattr(USERS[user_id], "policies")
        else []
    )
    if effective:
        group_policies = []
        for g_id, g in GROUPS.items():
            if user_id in g.get("members", []):
                group_policies.extend(g.get("policies", []))
        policies = list(set(direct + group_policies))
    else:
        policies = direct
    names = sorted([n for n in policies if (not prefix or n.startswith(prefix))])
    if after:
        names = [n for n in names if n > after]
    selected = names[:amount]
    has_more = len(names) > amount
    next_offset = selected[-1] if has_more else None
    return PolicyList(
        pagination=Pagination(
            next_offset=next_offset, results=len(selected), has_more=has_more
        ),
        results=[POLICIES[n] for n in selected],
    )


@app.put("/auth/users/{user_id}/policies/{policy_id}", status_code=201)
def attach_policy_to_user(user_id: str, policy_id: str):
    if user_id not in USERS or policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="not found")
    policies = getattr(USERS[user_id], "policies", [])
    if policy_id not in policies:
        policies.append(policy_id)
    USERS[user_id].__dict__["policies"] = policies
    return None


@app.delete("/auth/users/{user_id}/policies/{policy_id}", status_code=204)
def detach_policy_from_user(user_id: str, policy_id: str):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    policies = getattr(USERS[user_id], "policies", [])
    if policy_id in policies:
        policies.remove(policy_id)
    USERS[user_id].__dict__["policies"] = policies
    return None


# Credentials endpoints
@app.get("/auth/users/{user_id}/credentials", response_model=CredentialsList)
def list_credentials(
    user_id: str,
    prefix: Optional[str] = None,
    after: Optional[str] = None,
    amount: int = 1000,
):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    creds = [c for c in CREDENTIALS.values() if c.user_name == user_id]
    names = sorted(
        [
            c.access_key_id
            for c in creds
            if not prefix or c.access_key_id.startswith(prefix)
        ]
    )
    if after:
        names = [n for n in names if n > after]
    selected_keys = names[:amount]
    has_more = len(names) > amount
    next_offset = selected_keys[-1] if has_more else None
    selected = [CREDENTIALS[k] for k in selected_keys]
    return CredentialsList(
        pagination=Pagination(
            next_offset=next_offset, results=len(selected), has_more=has_more
        ),
        results=[
            Credentials(access_key_id=c.access_key_id, creation_date=c.creation_date)
            for c in selected
        ],
    )


@app.post(
    "/auth/users/{user_id}/credentials",
    response_model=CredentialsWithSecret,
    status_code=201,
)
def create_credentials(
    user_id: str, access_key: Optional[str] = None, secret_key: Optional[str] = None
):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    if not access_key:
        access_key = uuid.uuid4().hex
    if not secret_key:
        secret_key = uuid.uuid4().hex
    cred = CredentialsWithSecret(
        access_key_id=access_key,
        secret_access_key=secret_key,
        creation_date=now_ts(),
        user_name=user_id,
    )
    CREDENTIALS[access_key] = cred
    return cred


@app.delete("/auth/users/{user_id}/credentials/{access_key_id}", status_code=204)
def delete_credentials(user_id: str, access_key_id: str):
    cred = CREDENTIALS.get(access_key_id)
    if not cred or cred.user_name != user_id:
        raise HTTPException(status_code=404, detail="not found")
    CREDENTIALS.pop(access_key_id)
    return None


@app.get(
    "/auth/users/{user_id}/credentials/{access_key_id}", response_model=Credentials
)
def get_user_credential(user_id: str, access_key_id: str):
    cred = CREDENTIALS.get(access_key_id)
    if not cred or cred.user_name != user_id:
        raise HTTPException(status_code=404, detail="not found")
    return Credentials(
        access_key_id=cred.access_key_id, creation_date=cred.creation_date
    )


@app.get("/auth/credentials/{access_key_id}", response_model=CredentialsWithSecret)
def get_credential(access_key_id: str):
    cred = CREDENTIALS.get(access_key_id)
    if not cred:
        raise HTTPException(status_code=404, detail="not found")
    return cred


# Groups endpoints
@app.get("/auth/groups", response_model=GroupList)
def list_groups(
    prefix: Optional[str] = None, after: Optional[str] = None, amount: int = 1000
):
    names = sorted([n for n in GROUPS if (not prefix or n.startswith(prefix))])
    if after:
        names = [n for n in names if n > after]
    selected = names[:amount]
    has_more = len(names) > amount
    next_offset = selected[-1] if has_more else None
    results = [
        Group(
            id=n,
            name=n,
            description=GROUPS[n]["description"],
            creation_date=GROUPS[n]["creation_date"],
        )
        for n in selected
    ]
    return GroupList(
        pagination=Pagination(
            next_offset=next_offset, results=len(results), has_more=has_more
        ),
        results=results,
    )


@app.post("/auth/groups", response_model=Group, status_code=201)
def create_group(group: GroupCreation):
    if group.id in GROUPS:
        raise HTTPException(status_code=409, detail="group exists")
    data = {
        "description": group.description,
        "creation_date": now_ts(),
        "members": [],
        "policies": [],
    }
    GROUPS[group.id] = data
    return Group(
        id=group.id,
        name=group.id,
        description=group.description,
        creation_date=data["creation_date"],
    )


@app.get("/auth/groups/{group_id}", response_model=Group)
def get_group(group_id: str):
    g = GROUPS.get(group_id)
    if not g:
        raise HTTPException(status_code=404, detail="not found")
    return Group(
        id=group_id,
        name=group_id,
        description=g["description"],
        creation_date=g["creation_date"],
    )


@app.delete("/auth/groups/{group_id}", status_code=204)
def delete_group(group_id: str):
    if group_id not in GROUPS:
        raise HTTPException(status_code=404, detail="not found")
    GROUPS.pop(group_id)
    # remove membership from users if stored
    for user in USERS.values():
        memberships = getattr(user, "groups", None)
        if memberships and group_id in memberships:
            memberships.remove(group_id)
    return None


@app.put("/auth/groups/{group_id}/members/{user_id}", status_code=201)
def add_group_member(group_id: str, user_id: str):
    if group_id not in GROUPS or user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    members = GROUPS[group_id].setdefault("members", [])
    if user_id not in members:
        members.append(user_id)
    return None


@app.delete("/auth/groups/{group_id}/members/{user_id}", status_code=204)
def remove_group_member(group_id: str, user_id: str):
    if group_id not in GROUPS or user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    members = GROUPS[group_id].setdefault("members", [])
    if user_id in members:
        members.remove(user_id)
    return None


@app.get("/auth/groups/{group_id}/policies", response_model=PolicyList)
def list_group_policies(
    group_id: str,
    prefix: Optional[str] = None,
    after: Optional[str] = None,
    amount: int = 1000,
):
    g = GROUPS.get(group_id)
    if not g:
        raise HTTPException(status_code=404, detail="not found")
    policies = g.get("policies", [])
    names = sorted([n for n in policies if (not prefix or n.startswith(prefix))])
    if after:
        names = [n for n in names if n > after]
    selected = names[:amount]
    has_more = len(names) > amount
    next_offset = selected[-1] if has_more else None
    return PolicyList(
        pagination=Pagination(
            next_offset=next_offset, results=len(selected), has_more=has_more
        ),
        results=[POLICIES[n] for n in selected],
    )


@app.put("/auth/groups/{group_id}/policies/{policy_id}", status_code=201)
def attach_policy_to_group(group_id: str, policy_id: str):
    if group_id not in GROUPS or policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="not found")
    policies = GROUPS[group_id].setdefault("policies", [])
    if policy_id not in policies:
        policies.append(policy_id)
    return None


@app.delete("/auth/groups/{group_id}/policies/{policy_id}", status_code=204)
def detach_policy_from_group(group_id: str, policy_id: str):
    if group_id not in GROUPS:
        raise HTTPException(status_code=404, detail="not found")
    policies = GROUPS[group_id].setdefault("policies", [])
    if policy_id in policies:
        policies.remove(policy_id)
    return None


# Policies endpoints
@app.get("/auth/policies", response_model=PolicyList)
def list_policies(
    prefix: Optional[str] = None, after: Optional[str] = None, amount: int = 1000
):
    names = sorted([n for n in POLICIES if (not prefix or n.startswith(prefix))])
    if after:
        names = [n for n in names if n > after]
    selected = names[:amount]
    has_more = len(names) > amount
    next_offset = selected[-1] if has_more else None
    return PolicyList(
        pagination=Pagination(
            next_offset=next_offset, results=len(selected), has_more=has_more
        ),
        results=[POLICIES[n] for n in selected],
    )


@app.post("/auth/policies", response_model=Policy, status_code=201)
def create_policy(policy: Policy):
    if policy.name in POLICIES:
        raise HTTPException(status_code=409, detail="policy exists")
    p = Policy(name=policy.name, creation_date=now_ts(), acl=policy.acl)
    POLICIES[policy.name] = p
    return p


@app.get("/auth/policies/{policy_id}", response_model=Policy)
def get_policy(policy_id: str):
    p = POLICIES.get(policy_id)
    if not p:
        raise HTTPException(status_code=404, detail="not found")
    return p


@app.put("/auth/policies/{policy_id}", response_model=Policy)
def update_policy(policy_id: str, policy: Policy):
    if policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="not found")
    updated = Policy(
        name=policy_id, creation_date=POLICIES[policy_id].creation_date, acl=policy.acl
    )
    POLICIES[policy_id] = updated
    return updated


@app.delete("/auth/policies/{policy_id}", status_code=204)
def delete_policy(policy_id: str):
    if policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="not found")
    POLICIES.pop(policy_id)
    # remove from groups and users
    for g in GROUPS.values():
        if policy_id in g.get("policies", []):
            g["policies"].remove(policy_id)
    for u in USERS.values():
        policies = getattr(u, "policies", [])
        if policy_id in policies:
            policies.remove(policy_id)
        u.__dict__["policies"] = policies
    return None


@app.get("/_health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
