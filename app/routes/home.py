from fastapi import APIRouter, Request, HTTPException
from ..security import decode_jwt

router = APIRouter()

@router.get("/api/home")
async def home(request: Request):
    token = request.cookies.get("session")
    payload = decode_jwt(token) if token else None
    if not payload or payload.get("type") != "session":
        raise HTTPException(401, "Não autenticado")
    # payload["sub"] é userid
    return {"username": "current", "email": "hidden", "userid": payload["sub"]}
