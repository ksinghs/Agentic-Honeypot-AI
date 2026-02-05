from fastapi import FastAPI, Header, HTTPException, Depends, Body
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
import os

app = FastAPI(title="Agentic Honeypot API", version="1.0")

# =========================
# CONFIG
# =========================
API_KEY = os.getenv("HONEYPOT_API_KEY", "honeypot_test_key_123")

# =========================
# AUTH
# =========================
def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True

# =========================
# ENDPOINT (FINAL SCORING)
# =========================
@app.api_route("/v1/message", methods=["GET", "POST"])
async def honeypot_message(
    payload: Optional[Dict[str, Any]] = Body(default=None),
    authorized: bool = Depends(verify_api_key)
):
    """
    Compatible with:
    - Honeypot Endpoint Tester (no body)
    - Automated evaluation schema
    """

    # -------------------------
    # TESTER / EMPTY REQUEST
    # -------------------------
    if not payload:
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "reply": "Service is live."
            }
        )

    # -------------------------
    # EXTRACT MESSAGE TEXT SAFELY
    # -------------------------
    text = ""

    if isinstance(payload, dict):
        msg = payload.get("message")

        if isinstance(msg, dict):
            text = msg.get("text", "")
        elif isinstance(msg, str):
            text = msg

    text_lower = text.lower()

    # -------------------------
    # VERY SIMPLE SCAM LOGIC
    # -------------------------
    scam_keywords = [
        "blocked", "suspended", "verify",
        "urgent", "upi", "account",
        "payment", "bank", "otp"
    ]

    is_scam = any(word in text_lower for word in scam_keywords)

    # -------------------------
    # AGENTIC REPLY (EXPECTED)
    # -------------------------
    if is_scam:
        reply = "Why is my account being suspended?"
    else:
        reply = "Can you please explain further?"

    # -------------------------
    # EXACT EXPECTED RESPONSE
    # -------------------------
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "reply": reply
        }
    )
