from dataclasses import dataclass

from environs import Env


@dataclass
class Db:
    db_url: str
    redis_url: str


@dataclass
class SecretKey:
    key: str
    algorithm: str
    token_expire: str


@dataclass
class Config:
    db: Db
    key: SecretKey


def load_cfg(path: str = None):
    env = Env()
    env.read_env(path)

    return Config(
        db=Db(db_url=env.str("DATABASE_URL"), redis_url=env.str("REDIS_URL")),
        key=SecretKey(
            key=env.str("SECRET_KEY"),
            algorithm=env.str("ALGORITHM"),
            token_expire=env.str("ACCESS_TOKEN_EXPIRE_MINUTES"),
        ),
    )
