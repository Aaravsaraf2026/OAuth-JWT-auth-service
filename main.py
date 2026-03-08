from fastapi import FastAPI,Request
from repo.jwt import jwt_wrapper
from fastapi.responses import RedirectResponse, HTMLResponse
import uvicorn
from routes.login import router
from database.db import close_db, init_schema



app = FastAPI()
@app.on_event("startup")
async def startup():
    await init_schema()


@app.on_event("shutdown")
async def shutdown():
    await close_db()

@app.post("/logout")
async def logout():

    response = RedirectResponse("/login", status_code=303)

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return response

@app.get("/")
async def home(request: Request):

    token = request.cookies.get("access_token")
    print("cookies:", request.cookies)
    print("token:", token)

    if not token:
        return HTMLResponse("<h1>Login again Page</h1>")

    try:
        payload = jwt_wrapper.verify(token)
    except:
        return HTMLResponse("<h1>Login done Page</h1>")

    return {"message": "Welcome", "user": payload["sub"]}



@router.get("/login")
async def log_n():
    return HTMLResponse("<h1>Login Page</h1>")

app.include_router(router,tags=["Email Auth"])


if __name__ == "__main__":
    import os
    
    # Get port from environment or use default

    uvicorn.run(
        "main:app",
        # host=host,
        port=8000,
        reload=True
    )