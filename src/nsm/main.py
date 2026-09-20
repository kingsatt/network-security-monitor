from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

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


dashboard_dir = Path(__file__).parent / "dashboard"

app.mount(
    "/dashboard/static",
    StaticFiles(directory=dashboard_dir),
    name="dashboard-static",
)


@app.get("/")
def root():
    return {
        "message": "Network Security Monitor API is running"
    }


@app.get("/dashboard")
def dashboard():
    return FileResponse(
        dashboard_dir / "index.html"
    )