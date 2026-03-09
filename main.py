from fastapi import FastAPI,Request
from repo.jwt import jwt_wrapper
from fastapi.responses import RedirectResponse, HTMLResponse
import uvicorn
from contextlib import asynccontextmanager
import repo.auth as auth
from routes.login import router
from routes.google_auth import api
from database.db import close_db, init_schema


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    oauth = auth.setup()        # ✅ runs first
    await oauth.initialize()
    await init_schema()
    yield
    await close_db()
    await oauth.shutdown()

app = FastAPI(lifespan=lifespan)

from security.middleware import SecurityMiddleware

app.add_middleware(SecurityMiddleware)



@app.post("/logout")
async def logout():

    response = RedirectResponse("/", status_code=303)

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return response





app.include_router(router,tags=["Email Auth"])
app.include_router(api,tags=["Email Auth"])


if __name__ == "__main__":
    import os
    
    # Get port from environment or use default

    uvicorn.run(
        "main:app",
        # host=host,
        port=8000,
        reload=True
    )

