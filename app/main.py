from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import auth

app = FastAPI(title="Auth + MFA (FastAPI)")

@app.get("/healthz", include_in_schema=False)
async def healthz():
    return PlainTextResponse("OK", status_code=200)

@app.head("/healthz", include_in_schema=False)
async def healthz_head():
    return PlainTextResponse("", status_code=200)

ALLOWED_ORIGINS = [
    "https://mfacloud.netlify.app",
    "https://dashboard-io-t-silos-front-g8b87imzs.vercel.app",
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
