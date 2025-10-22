import os
from pydantic import BaseSettings, AnyUrl

class Settings(BaseSettings):
    MONGODB_URI: AnyUrl
    APP_SECRET_KEY: str
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    SMTP_HOST: str
    SMTP_PORT: int = 587
    SMTP_USER: str
    SMTP_PASSWORD: str
    FROM_EMAIL: str
    PORT: int = int(os.getenv("PORT", "8000"))
    FRONTEND_URL: str = "http://localhost:3000"
    RENDER: bool = os.getenv("RENDER", "false").lower() == "true"
    ISSUER: str = "StudyAuthApp"

    EMAIL_CONFIRM_EXP_HOURS: int = 24
    PASSWORD_RESET_EXP_MIN: int = 60
    MFA_TEMP_EXP_MIN: int = 5
    SESSION_EXP_MIN: int = 60

    class Config:
        env_file = ".env"

settings = Settings()
