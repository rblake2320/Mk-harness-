"""MK Consultant Harness API."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings, require_secret
from .db import init_engine
from .routes import auth, chat, customers, keys, profile, skin, usage


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    require_secret(settings)
    settings.master_key_bytes  # fail fast if missing/malformed
    init_engine()
    yield


app = FastAPI(title="MK Consultant Harness", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)

for r in (auth.router, chat.router, skin.router, customers.router,
          keys.router, usage.router, profile.router):
    app.include_router(r, prefix="/api")


@app.get("/api/health")
def health():
    return {"status": "ok"}
