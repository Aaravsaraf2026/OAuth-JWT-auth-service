from fastapi import FastAPI
import uvicorn
from routes.login import router


app = FastAPI()

@app.get("/")
def testapp():
    return "run successfully"

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