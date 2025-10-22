# security.py corrigido

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
import pyotp
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from bson import ObjectId
from .config import settings
from app.db import users


pwd_context = CryptContext(schemes=["bcrypt_sha256", "bcrypt"], deprecated="auto")
security = HTTPBearer()


def hash_password(p: str) -> str:
    return pwd_context.hash(p)


def verify_password(p: str, h: str) -> bool:
    return pwd_context.verify(p, h)


def create_jwt(sub: str, claims: dict = None, minutes: int = 60) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": sub,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
        "iss": settings.ISSUER
    }
    if claims:
        payload.update(claims)
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_jwt(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM], issuer=settings.ISSUER)
    except JWTError:
        return None


def mfa_generate_secret() -> str:
    return pyotp.random_base32()


def mfa_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def mfa_verify_code(secret: str, code: str, valid_window: int = 1) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=valid_window)


def random_token_urlsafe(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def get_current_user(token: str = Depends(security)):
    payload = decode_jwt(token.credentials)
    if not payload or payload.get("type") != "session":
        raise HTTPException(401, "Token inválido")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(401, "Token inválido")
    user = await users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(404, "Usuário não encontrado")
    return user
