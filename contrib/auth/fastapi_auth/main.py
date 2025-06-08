from fastapi import FastAPI, HTTPException, APIRouter
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uuid
import os
from sqlalchemy import (
    create_engine,
    Table,
    Column,
    String,
    Integer,
    Text,
    MetaData,
    ForeignKey,
)


app = FastAPI(title="lakeFS ACL Auth Server")
api = APIRouter(prefix="/api/v1")

# In-memory storage
USERS = {}
GROUPS = {}
POLICIES = {}
CREDENTIALS = {}

# Storage configuration
STORE = os.getenv("FASTAPI_AUTH_STORAGE", "memory").lower()
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://auth:auth@localhost/auth")
engine = None
metadata = MetaData()
if STORE == "postgres":
    engine = create_engine(DATABASE_URL)
    users_table = Table(
        "users",
        metadata,
        Column("username", String, primary_key=True),
        Column("creation_date", Integer),
        Column("friendly_name", String),
        Column("email", String),
        Column("source", String),
    )
    groups_table = Table(
        "groups",
        metadata,
        Column("id", String, primary_key=True),
        Column("description", String),
        Column("creation_date", Integer),
    )
    group_members_table = Table(
        "group_members",
        metadata,
        Column("group_id", String, ForeignKey("groups.id")),
        Column("user_id", String, ForeignKey("users.username")),
    )
    policies_table = Table(
        "policies",
        metadata,
        Column("name", String, primary_key=True),
        Column("creation_date", Integer),
        Column("acl", Text),
    )
    user_policies_table = Table(
        "user_policies",
        metadata,
        Column("user_id", String, ForeignKey("users.username")),
        Column("policy_id", String, ForeignKey("policies.name")),
    )
    group_policies_table = Table(
        "group_policies",
        metadata,
        Column("group_id", String, ForeignKey("groups.id")),
        Column("policy_id", String, ForeignKey("policies.name")),
    )
    credentials_table = Table(
        "credentials",
        metadata,
        Column("access_key_id", String, primary_key=True),
        Column("secret_access_key", String),
        Column("creation_date", Integer),
        Column("user_name", String, ForeignKey("users.username")),
    )
    metadata.create_all(engine)

    def load_from_db():
        with engine.begin() as conn:
            USERS.update(
                {
                    r.username: User(
                        username=r.username,
                        creation_date=r.creation_date,
                        friendly_name=r.friendly_name,
                        email=r.email,
                        source=r.source,
                    )
                    for r in conn.execute(users_table.select())
                }
            )
            GROUPS.clear()
            for r in conn.execute(groups_table.select()):
                GROUPS[r.id] = {
                    "description": r.description,
                    "creation_date": r.creation_date,
                    "members": [],
                    "policies": [],
                }
            for r in conn.execute(group_members_table.select()):
                GROUPS[r.group_id].setdefault("members", []).append(r.user_id)
            POLICIES.update(
                {
                    r.name: Policy(
                        name=r.name,
                        creation_date=r.creation_date,
                        acl=r.acl,
                    )
                    for r in conn.execute(policies_table.select())
                }
            )
            for r in conn.execute(user_policies_table.select()):
                USERS[r.user_id].__dict__.setdefault("policies", []).append(
                    r.policy_id
                )
            for r in conn.execute(group_policies_table.select()):
                GROUPS[r.group_id].setdefault("policies", []).append(r.policy_id)
            CREDENTIALS.update(
                {
                    r.access_key_id: CredentialsWithSecret(
                        access_key_id=r.access_key_id,
                        secret_access_key=r.secret_access_key,
                        creation_date=r.creation_date,
                        user_name=r.user_name,
                    )
                    for r in conn.execute(credentials_table.select())
                }
            )

    def sync_db():
        with engine.begin() as conn:
            conn.execute(users_table.delete())
            for u in USERS.values():
                conn.execute(users_table.insert().values(**u.dict()))

            conn.execute(groups_table.delete())
            for gid, g in GROUPS.items():
                conn.execute(
                    groups_table.insert().values(
                        id=gid,
                        description=g["description"],
                        creation_date=g["creation_date"],
                    )
                )

            conn.execute(group_members_table.delete())
            for gid, g in GROUPS.items():
                for member in g.get("members", []):
                    conn.execute(
                        group_members_table.insert().values(
                            group_id=gid, user_id=member
                        )
                    )

            conn.execute(policies_table.delete())
            for p in POLICIES.values():
                conn.execute(policies_table.insert().values(**p.dict()))

            conn.execute(user_policies_table.delete())
            for uname, u in USERS.items():
                for p in getattr(u, "policies", []):
                    conn.execute(
                        user_policies_table.insert().values(
                            user_id=uname, policy_id=p
                        )
                    )

            conn.execute(group_policies_table.delete())
            for gid, g in GROUPS.items():
                for p in g.get("policies", []):
                    conn.execute(
                        group_policies_table.insert().values(
                            group_id=gid, policy_id=p
                        )
                    )

            conn.execute(credentials_table.delete())
            for c in CREDENTIALS.values():
                conn.execute(credentials_table.insert().values(**c.dict()))

    load_from_db()


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
@api.get("/auth/users", response_model=UserList)
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


@api.post("/auth/users", response_model=User, status_code=201)
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
    if STORE == "postgres":
        sync_db()
    return u


@api.get("/auth/users/{user_id}", response_model=User)
def get_user(user_id: str):
    u = USERS.get(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="not found")
    return u


@api.delete("/auth/users/{user_id}", status_code=204)
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
    if STORE == "postgres":
        sync_db()
    return None


@api.get("/auth/users/{user_id}/groups", response_model=GroupList)
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


@api.get("/auth/users/{user_id}/policies", response_model=PolicyList)
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


@api.put("/auth/users/{user_id}/policies/{policy_id}", status_code=201)
def attach_policy_to_user(user_id: str, policy_id: str):
    if user_id not in USERS or policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="not found")
    policies = getattr(USERS[user_id], "policies", [])
    if policy_id not in policies:
        policies.append(policy_id)
    USERS[user_id].__dict__["policies"] = policies
    if STORE == "postgres":
        sync_db()
    return None


@api.delete("/auth/users/{user_id}/policies/{policy_id}", status_code=204)
def detach_policy_from_user(user_id: str, policy_id: str):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    policies = getattr(USERS[user_id], "policies", [])
    if policy_id in policies:
        policies.remove(policy_id)
    USERS[user_id].__dict__["policies"] = policies
    if STORE == "postgres":
        sync_db()
    return None


# Credentials endpoints
@api.get("/auth/users/{user_id}/credentials", response_model=CredentialsList)
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


@api.post(
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
    if STORE == "postgres":
        sync_db()
    return cred


@api.delete("/auth/users/{user_id}/credentials/{access_key_id}", status_code=204)
def delete_credentials(user_id: str, access_key_id: str):
    cred = CREDENTIALS.get(access_key_id)
    if not cred or cred.user_name != user_id:
        raise HTTPException(status_code=404, detail="not found")
    CREDENTIALS.pop(access_key_id)
    if STORE == "postgres":
        sync_db()
    return None


@api.get(
    "/auth/users/{user_id}/credentials/{access_key_id}", response_model=Credentials
)
def get_user_credential(user_id: str, access_key_id: str):
    cred = CREDENTIALS.get(access_key_id)
    if not cred or cred.user_name != user_id:
        raise HTTPException(status_code=404, detail="not found")
    return Credentials(
        access_key_id=cred.access_key_id, creation_date=cred.creation_date
    )


@api.get("/auth/credentials/{access_key_id}", response_model=CredentialsWithSecret)
def get_credential(access_key_id: str):
    cred = CREDENTIALS.get(access_key_id)
    if not cred:
        raise HTTPException(status_code=404, detail="not found")
    return cred


# Groups endpoints
@api.get("/auth/groups", response_model=GroupList)
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


@api.post("/auth/groups", response_model=Group, status_code=201)
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
    if STORE == "postgres":
        sync_db()
    return Group(
        id=group.id,
        name=group.id,
        description=group.description,
        creation_date=data["creation_date"],
    )


@api.get("/auth/groups/{group_id}", response_model=Group)
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


@api.delete("/auth/groups/{group_id}", status_code=204)
def delete_group(group_id: str):
    if group_id not in GROUPS:
        raise HTTPException(status_code=404, detail="not found")
    GROUPS.pop(group_id)
    # remove membership from users if stored
    for user in USERS.values():
        memberships = getattr(user, "groups", None)
        if memberships and group_id in memberships:
            memberships.remove(group_id)
    if STORE == "postgres":
        sync_db()
    return None


@api.put("/auth/groups/{group_id}/members/{user_id}", status_code=201)
def add_group_member(group_id: str, user_id: str):
    if group_id not in GROUPS or user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    members = GROUPS[group_id].setdefault("members", [])
    if user_id not in members:
        members.append(user_id)
    if STORE == "postgres":
        sync_db()
    return None


@api.delete("/auth/groups/{group_id}/members/{user_id}", status_code=204)
def remove_group_member(group_id: str, user_id: str):
    if group_id not in GROUPS or user_id not in USERS:
        raise HTTPException(status_code=404, detail="not found")
    members = GROUPS[group_id].setdefault("members", [])
    if user_id in members:
        members.remove(user_id)
    if STORE == "postgres":
        sync_db()
    return None


@api.get("/auth/groups/{group_id}/policies", response_model=PolicyList)
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


@api.put("/auth/groups/{group_id}/policies/{policy_id}", status_code=201)
def attach_policy_to_group(group_id: str, policy_id: str):
    if group_id not in GROUPS or policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="not found")
    policies = GROUPS[group_id].setdefault("policies", [])
    if policy_id not in policies:
        policies.append(policy_id)
    if STORE == "postgres":
        sync_db()
    return None


@api.delete("/auth/groups/{group_id}/policies/{policy_id}", status_code=204)
def detach_policy_from_group(group_id: str, policy_id: str):
    if group_id not in GROUPS:
        raise HTTPException(status_code=404, detail="not found")
    policies = GROUPS[group_id].setdefault("policies", [])
    if policy_id in policies:
        policies.remove(policy_id)
    if STORE == "postgres":
        sync_db()
    return None


# Policies endpoints
@api.get("/auth/policies", response_model=PolicyList)
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


@api.post("/auth/policies", response_model=Policy, status_code=201)
def create_policy(policy: Policy):
    if policy.name in POLICIES:
        raise HTTPException(status_code=409, detail="policy exists")
    p = Policy(name=policy.name, creation_date=now_ts(), acl=policy.acl)
    POLICIES[policy.name] = p
    if STORE == "postgres":
        sync_db()
    return p


@api.get("/auth/policies/{policy_id}", response_model=Policy)
def get_policy(policy_id: str):
    p = POLICIES.get(policy_id)
    if not p:
        raise HTTPException(status_code=404, detail="not found")
    return p


@api.put("/auth/policies/{policy_id}", response_model=Policy)
def update_policy(policy_id: str, policy: Policy):
    if policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="not found")
    updated = Policy(
        name=policy_id, creation_date=POLICIES[policy_id].creation_date, acl=policy.acl
    )
    POLICIES[policy_id] = updated
    if STORE == "postgres":
        sync_db()
    return updated


@api.delete("/auth/policies/{policy_id}", status_code=204)
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
    if STORE == "postgres":
        sync_db()
    return None


@api.get("/health")
@api.get("/_health")
def health():
    return {"status": "ok"}
app.include_router(api)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
