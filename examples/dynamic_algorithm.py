from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.exceptions import AuthJWTException
from async_fastapi_jwt_auth.auth_jwt import AuthJWTBearer

app = FastAPI()
auth_dep = AuthJWTBearer()


class User(BaseModel):
    username: str
    password: str


class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    # Configure algorithms which is permit
    authjwt_decode_algorithms: set = {"HS384", "HS512"}


@AuthJWT.load_config
def get_config():
    return Settings()


@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.post("/login")
async def login(user: User, authorize: AuthJWT = Depends(auth_dep)):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    # You can define different algorithm when create a token
    access_token = await authorize.create_access_token(
        subject=user.username, algorithm="HS384"
    )
    refresh_token = await authorize.create_refresh_token(
        subject=user.username, algorithm="HS512"
    )
    return {"access_token": access_token, "refresh_token": refresh_token}


# In protected route, automatically check incoming JWT
# have algorithm in your `authjwt_decode_algorithms` or not
@app.post("/refresh")
async def refresh(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_refresh_token_required()

    current_user = await authorize.get_jwt_subject()
    new_access_token = await authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}


# In protected route, automatically check incoming JWT
# have algorithm in your `authjwt_decode_algorithms` or not
@app.get("/protected")
async def protected(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_required()

    current_user = await authorize.get_jwt_subject()
    return {"user": current_user}