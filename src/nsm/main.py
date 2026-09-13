from fastapi import FastAPI

from nsm.api.routes import router
from nsm.db.database import Base, engine
from nsm.db import models

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Network Security Monitor",
    description="Network scanning and security monitoring API",
    version="1.0.0",
)

app.include_router(router)


@app.get("/")
def root():
    return {"message": "Network Security Monitor API is running"}