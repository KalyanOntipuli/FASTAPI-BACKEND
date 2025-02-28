from fastapi import FastAPI
from infra.database import Base, engine

app = FastAPI()

Base.metadata.create_all(bind=engine)
