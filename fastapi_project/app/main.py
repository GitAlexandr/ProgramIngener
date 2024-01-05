import logging
import time
from datetime import datetime, timedelta
from urllib.request import Request

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from db.db_con import SessionLocal, get_db
from models.user import User
from schemas.validation import Token, UserCreate, UserResponse
from ProgramIngener.fastapi_project.utils.config import load_cfg
from ProgramIngener.fastapi_project.utils.users import hash_password, validate_password

config = load_cfg()

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, config.key.key, algorithms=[config.key.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username


@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: SessionLocal = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    db_user_email = db.query(User).filter(User.email == user.email).first()
    if db_user_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = hash_password(user.password)
    db_user = User(**user.dict(), hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordBearer = Depends()):
    db = SessionLocal()
    user = authenticate_user(form_data.username, form_data.password, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=int(config.key.token_expire))
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


def authenticate_user(username: str, password: str):
    user = User.query.filter_by(username=username).first()
    if user and validate_password(password, user.hashed_password):
        return user


@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: str = Depends(get_current_user)):
    return {"username": current_user}


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, config.key.key, algorithm=config.key.algorithm)
    return encoded_jwt


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time

    logger.info(
        f"Method: {request.method}, "
        f"Path: {request.url.path}, "
        f"Status Code: {response.status_code}, "
        f"Process Time: {process_time:.2f} seconds"
    )

    return response
