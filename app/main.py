from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from .routes import auth, home
from .config import settings

app = FastAPI(title="Auth + MFA (FastAPI)")

# CORS apenas se necessário para front em domínio separado
ALLOWED_ORIGINS = [
    "https://mfacloud.netlify.app/"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS, 
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"], 
    max_age=600,
)

app.include_router(auth.router)
app.include_router(home.router)
