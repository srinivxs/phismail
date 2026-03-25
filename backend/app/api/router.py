"""
PhisMail — Route Aggregation
Combines all API route modules.
"""

from fastapi import APIRouter
from app.api.analysis import router as analysis_router
from app.api.reports import router as reports_router
from app.api.health import router as health_router
from app.api.ml import router as ml_router
from app.api.auth_routes import router as auth_router

api_router = APIRouter()
api_router.include_router(analysis_router)
api_router.include_router(reports_router)
api_router.include_router(health_router)
api_router.include_router(ml_router)
api_router.include_router(auth_router)
