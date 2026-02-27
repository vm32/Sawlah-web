import jwt
import os
from datetime import datetime, timezone, timedelta
from passlib.hash import pbkdf2_sha256
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

SECRET_KEY = os.environ.get("SAWLAH_SECRET", "sawlah-dev-secret-change-me-in-prod")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

users_db: dict[str, dict] = {}

router = APIRouter()

def _init_default_user():
    if not users_db:
        users_db["admin"] = {
            "username": "admin",
            "password_hash": pbkdf2_sha256.hash("sawlah"),
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

_init_default_user()


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(request: Request) -> dict:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth_header[7:]
    payload = verify_token(token)
    username = payload.get("sub")
    user = users_db.get(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@router.post("/login")
async def login(req: LoginRequest):
    user = users_db.get(req.username)
    if not user or not pbkdf2_sha256.verify(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(req.username)
    return {"token": token, "username": req.username, "role": user["role"]}


@router.post("/register")
async def register(req: RegisterRequest):
    if req.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    users_db[req.username] = {
        "username": req.username,
        "password_hash": pbkdf2_sha256.hash(req.password),
        "role": "user",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    token = create_token(req.username)
    return {"token": token, "username": req.username, "role": "user"}


@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return {"username": user["username"], "role": user["role"]}


@router.post("/change-password")
async def change_password(data: dict, user: dict = Depends(get_current_user)):
    old_pw = data.get("old_password", "")
    new_pw = data.get("new_password", "")
    if not pbkdf2_sha256.verify(old_pw, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Wrong current password")
    users_db[user["username"]]["password_hash"] = pbkdf2_sha256.hash(new_pw)
    return {"status": "ok"}
