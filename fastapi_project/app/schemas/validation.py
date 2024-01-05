from datetime import datetime
from typing import Optional

from pydantic import UUID4, BaseModel, EmailStr, Field, validator


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserInDB(UserCreate):
    hashed_password: str


class UserResponse(BaseModel):
    username: str
    email: EmailStr
    created_at: datetime


class Token(BaseModel):
    access_token: UUID4 = Field(..., alias="access_token")
    token_type: Optional[str] = "bearer"

    class Config:
        allow_population_by_field_name = True

    @validator("token")
    def hexlify_token(cls, value):
        return value.hex


class TokenData(BaseModel):
    username: str | None = None
