# auth.py completo corrigido

import pyotp
from fastapi import APIRouter, HTTPException, Request, Response, Depends
from datetime import datetime, timedelta
from bson import ObjectId
from uuid import uuid4
from ..models import *
from ..db import users
from ..security import *
from ..rate_limit import is_allowed
from ..utils.emailer import send_email
from ..config import settings

router = APIRouter()

def cookie_params():
    return {
        "httponly": True,
        "secure": True if settings.RENDER else False,
        "samesite": "none" if settings.RENDER else "lax",
        "path": "/",
    }

async def find_user_by_username(username: str):
    return await users.find_one({"username": username})

async def find_user_by_email(email: str):
    return await users.find_one({"email": email})

@router.post("/api/register")
async def register(payload: UserCreate):
    if not is_allowed(f"reg:{payload.email}", 5, 15*60):
        raise HTTPException(429, "Muitas tentativas, tente mais tarde")
    if await find_user_by_username(payload.username):
        raise HTTPException(400, "username já existe")
    if await find_user_by_email(payload.email):
        raise HTTPException(400, "email já cadastrado")

    userid = str(uuid4())
    now = datetime.utcnow()
    email_token = random_token_urlsafe(32)
    email_token_hash = hash_token(email_token)
    email_exp = now + timedelta(hours=settings.EMAIL_CONFIRM_EXP_HOURS)

    doc = {
        "userid": userid,
        "username": payload.username,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "email_verified": False,
        "email_confirm_token": email_token_hash,
        "email_confirm_expires": email_exp,
        "mfa_enabled": False,
        "mfa_secret": None,
        "mfa_backup_codes": [],
        "created_at": now,
        "updated_at": now,
        "password_reset_token": None,
        "password_reset_expires": None,
    }
    await users.insert_one(doc)

    confirm_link = f"https://cloud-project-web-mfa-backend.onrender.com/confirm-email?token={email_token}"
    email_html = f"""
    <h3>Confirme seu e-mail</h3>
    <p>Clique para confirmar: {confirm_link}</p>
    <p>Se não foi você, ignore este e-mail.</p>
    """
    send_email(payload.email, "Confirme seu e-mail", email_html)

    return {"ok": True}

@router.get("/confirm-email")
async def confirm_email(token: str, response: Response):
    token_hash = hash_token(token)
    now = datetime.utcnow()
    user = await users.find_one({
        "email_confirm_token": token_hash,
        "email_confirm_expires": {"$gt": now},
        "email_verified": False,
    })
    if not user:
        raise HTTPException(400, "Token inválido ou expirado")

    await users.update_one({"_id": user["_id"]}, {"$set": {
        "email_verified": True,
        "email_confirm_token": None,
        "email_confirm_expires": None,
        "updated_at": now,
    }})

    temp = create_jwt(str(user["_id"]), {"type": "mfa_enroll", "username": user["username"]}, minutes=15)
    response.headers["Location"] = f"{settings.FRONTEND_URL}/mfa-enroll.html?temp={temp}"
    return Response(status_code=302)

@router.get("/mfa/enroll")
async def mfa_enroll(request: Request):
    token = request.query_params.get("temp")
    payload = decode_jwt(token) if token else None
    if not payload or payload.get("type") != "mfa_enroll":
        raise HTTPException(401, "Token inválido para enrolamento MFA")

    user = await users.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(404, "Usuário não encontrado")

    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user["username"], issuer_name="SeuApp"
    )

    await users.update_one(
        {"_id": user["_id"]}, {"$set": {"mfa_secret_temp": secret}}
    )

    import qrcode
    from io import BytesIO
    import base64

    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_png_data_uri": f"data:image/png;base64,{qr_b64}",
        "username": user["username"]
    }

@router.get("/api/mfa/enroll-token")
async def get_mfa_enroll_token(current_user=Depends(get_current_user)):
    temp_token = create_jwt(str(current_user["_id"]), {"type": "mfa_enroll", "username": current_user["username"]}, minutes=15)
    return {"temp_token": temp_token}

@router.post("/api/mfa/enroll")
async def mfa_enroll_confirm(body: MFAEnrollVerify):
    user = await users.find_one({"username": body.username})
    if not user or "mfa_secret_temp" not in user or not user["mfa_secret_temp"]:
        raise HTTPException(400, "Enrolamento não iniciado")

    secret = user["mfa_secret_temp"]
    totp = pyotp.TOTP(secret)
    if not totp.verify(body.code):
        raise HTTPException(400, "Código TOTP inválido")

    backup_codes_raw = [random_token_urlsafe(10) for _ in range(10)]
    backup_codes_hashed = [hash_token(c) for c in backup_codes_raw]

    await users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "mfa_enabled": True,
                "mfa_secret": secret,
                "mfa_backup_codes": backup_codes_hashed,
            },
            "$unset": {"mfa_secret_temp": ""},
        },
    )
    return {"ok": True, "backup_codes": backup_codes_raw}

@router.get("/api/home")
async def home(current_user=Depends(get_current_user)):
    if not current_user.get("email_verified", False):
        raise HTTPException(403, "E-mail não confirmado")
    return {
        "userid": current_user.get("userid"),
        "username": current_user.get("username"),
        "email": current_user.get("email"),
        "mfa_enabled": current_user.get("mfa_enabled", False),
    }

@router.post("/api/login")
async def login(payload: UserLogin, response: Response, request: Request):
    key_ip = f"login_ip:{request.client.host}"
    key_user = f"login_user:{payload.username}"
    if not is_allowed(key_ip, 10, 15*60) or not is_allowed(key_user, 5, 15*60):
        raise HTTPException(429, "Muitas tentativas, tente mais tarde")

    user = await find_user_by_username(payload.username)
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(401, "Credenciais inválidas")

    if not user.get("email_verified"):
        raise HTTPException(403, "E-mail não confirmado")

    if user.get("mfa_enabled"):
        temp = create_jwt(str(user["_id"]), {"type": "mfa_challenge", "username": user["username"]}, minutes=settings.MFA_TEMP_EXP_MIN)
        return {"mfa_required": True, "temp_token": temp}

    session = create_jwt(str(user["_id"]), {"type": "session"}, minutes=settings.SESSION_EXP_MIN)
    response.set_cookie("session", session, **cookie_params())
    return {"ok": True}

@router.post("/api/mfa/verify")
async def mfa_verify(body: MFAVerify, response: Response):
    payload = decode_jwt(body.temp_token)
    if not payload or payload.get("type") != "mfa_challenge":
        raise HTTPException(401, "Desafio inválido")

    user = await users.find_one({"_id": ObjectId(payload["sub"])})
    if not user or not user.get("mfa_enabled") or not user.get("mfa_secret"):
        raise HTTPException(400, "Estado MFA inválido")

    code = body.code.strip()
    is_code = code.isdigit() and mfa_verify_code(user["mfa_secret"], code, valid_window=1)
    is_backup = False
    if not is_code:
        h = hash_token(code)
        if h in user.get("mfa_backup_codes", []):
            is_backup = True
            await users.update_one({"_id": user["_id"]}, {"$pull": {"mfa_backup_codes": h}})

    if not (is_code or is_backup):
        raise HTTPException(400, "Código inválido")

    session = create_jwt(str(user["_id"]), {"type": "session"}, minutes=settings.SESSION_EXP_MIN)
    response.set_cookie("session", session, **cookie_params())
    return {"ok": True}

@router.post("/api/password-reset-request")
async def password_reset_request(body: PasswordResetRequest):
    if not is_allowed(f"pwreset:{body.email}", 3, 60*60):
        raise HTTPException(429, "Limite de solicitações atingido")
    user = await find_user_by_email(body.email)
    if user:
        tok = random_token_urlsafe(32)
        now = datetime.utcnow()
        await users.update_one({"_id": user["_id"]}, {"$set": {
            "password_reset_token": hash_token(tok),
            "password_reset_expires": now + timedelta(minutes=settings.PASSWORD_RESET_EXP_MIN),
            "updated_at": now,
        }})
        reset_link = f"/reset-password?token={tok}"
        email_html = f"<p>Redefina sua senha: {reset_link}</p>"
        send_email(user["email"], "Redefinição de senha", email_html)
    return {"ok": True}

@router.post("/api/reset-password")
async def reset_password(body: PasswordResetSubmit):
    now = datetime.utcnow()
    user = await users.find_one({
        "password_reset_token": hash_token(body.token),
        "password_reset_expires": {"$gt": now}
    })
    if not user:
        raise HTTPException(400, "Token inválido ou expirado")

    await users.update_one({"_id": user["_id"]}, {"$set": {
        "password_hash": hash_password(body.new_password),
        "password_reset_token": None,
        "password_reset_expires": None,
        "updated_at": now,
    }})
    return {"ok": True}
