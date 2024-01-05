from ProgramIngener.fastapi_project.utils.config import load_cfg
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

config = load_cfg()
engine = create_engine(config.db.db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
