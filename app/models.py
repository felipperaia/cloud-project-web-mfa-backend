from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class MFAEnrollStart(BaseModel):
    pass

class MFAVerify(BaseModel):
    temp_token: str
    code: str

class MFAEnrollVerify(BaseModel):
    code: str
    username: str
class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetSubmit(BaseModel):
    token: str
    new_password: str

class UserPublic(BaseModel):
    userid: str
    username: str
    email: EmailStr