from fastapi import APIRouter

from app.api.v1.endpoints import admin, auth, kiosk, kiosk_admin, vc

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(vc.router)
api_router.include_router(admin.router)
api_router.include_router(kiosk_admin.router)
api_router.include_router(kiosk.router)
