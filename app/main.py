from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import auth, home

app = FastAPI(title="Auth + MFA (FastAPI)")

ALLOWED_ORIGINS = [
    "https://mfacloud.netlify.app",
    # "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)

app.include_router(auth.router)
app.include_router(home.router)
