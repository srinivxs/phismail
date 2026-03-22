"""
PhisMail — ML API Endpoints
User feedback, model stats, and model management.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.ml.ml_integration import get_ml_integration

router = APIRouter(prefix="/ml", tags=["ml"])


class FeedbackRequest(BaseModel):
    analysis_id: str
    label: str  # "PHISHING" or "LEGITIMATE"
    notes: Optional[str] = None


@router.post("/feedback")
async def submit_feedback(request: FeedbackRequest):
    """Submit user feedback on an ML prediction."""
    if request.label not in ("PHISHING", "LEGITIMATE"):
        raise HTTPException(400, "Label must be PHISHING or LEGITIMATE")

    ml = get_ml_integration()
    ml.record_feedback(request.analysis_id, request.label, request.notes)
    return {"status": "success", "message": "Feedback recorded"}


@router.get("/stats")
async def get_stats():
    """Get ML model performance statistics."""
    ml = get_ml_integration()
    return ml.get_model_stats()


@router.post("/reload-model")
async def reload_model():
    """Reload ML model after retraining."""
    try:
        ml = get_ml_integration()
        ml.reload_model()
        return {"status": "success", "message": "Model reloaded"}
    except Exception as exc:
        raise HTTPException(500, f"Model reload failed: {exc}")
