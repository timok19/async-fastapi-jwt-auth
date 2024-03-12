from fastapi import APIRouter, Depends

from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.auth_jwt import AuthJWTBearer


router = APIRouter()
auth_dep = AuthJWTBearer()


@router.get("/items")
async def items(authorize: AuthJWT = Depends(auth_dep)):
    await authorize.jwt_required()

    items = ["item1", "item2", "item3"]

    return {"items": items}
