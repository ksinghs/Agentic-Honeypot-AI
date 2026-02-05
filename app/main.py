from fastapi import FastAPI, Header, HTTPException, Depends, Body
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import re
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
# MODELS
# =========================
class MessageInput(BaseModel):
    conversation_id: str
    message: str
    timestamp: Optional[str] = None

class EngagementMetrics(BaseModel):
    turn_count: int
    engagement_duration_sec: int

class ExtractedIntelligence(BaseModel):
    upi_ids: List[str]
    bank_accounts: List[str]
    phishing_urls: List[str]

class HoneypotResponse(BaseModel):
    conversation_id: str
    scam_detected: bool
    confidence_score: float
    agent_active: bool
    engagement_metrics: EngagementMetrics
    extracted_intelligence: ExtractedIntelligence
    agent_reply: str

# =========================
# SIMPLE IN-MEMORY STATE
# =========================
conversation_state: Dict[str, Dict] = {}

# =========================
# UTILS
# =========================
SCAM_KEYWORDS = [
    "blocked", "suspended", "urgent", "verify",
    "upi", "account", "payment", "bank",
    "click", "link", "otp"
]

UPI_REGEX = re.compile(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}")
URL_REGEX = re.compile(r"https?://\S+")

def detect_scam(text: str) -> float:
    score = 0.0
    lowered = text.lower()
    for kw in SCAM_KEYWORDS:
        if kw in lowered:
            score += 0.15
    return min(score, 1.0)

def extract_intel(text: str):
    return {
        "upi_ids": list(set(UPI_REGEX.findall(text))),
        "bank_accounts": [],
        "phishing_urls": list(set(URL_REGEX.findall(text)))
    }

# =========================
# ENDPOINT
# =========================
@app.post("/v1/message", response_model=HoneypotResponse)
async def honeypot_message(
    payload: Optional[MessageInput] = Body(default=None),
    authorized: bool = Depends(verify_api_key)
):
    # -------------------------
    # TESTER SAFE PATH (NO BODY)
    # -------------------------
    if payload is None:
        return HoneypotResponse(
            conversation_id="tester",
            scam_detected=False,
            confidence_score=0.0,
            agent_active=False,
            engagement_metrics=EngagementMetrics(
                turn_count=0,
                engagement_duration_sec=0
            ),
            extracted_intelligence=ExtractedIntelligence(
                upi_ids=[],
                bank_accounts=[],
                phishing_urls=[]
            ),
            agent_reply="Service is live and ready."
        )

    # -------------------------
    # NORMAL EVALUATION PATH
    # -------------------------
    cid = payload.conversation_id
    msg = payload.message

    if cid not in conversation_state:
        conversation_state[cid] = {
            "turns": 0,
            "start_time": datetime.utcnow(),
            "confidence": 0.0,
            "active": False
        }

    state = conversation_state[cid]
    state["turns"] += 1

    scam_score = detect_scam(msg)
    state["confidence"] = max(state["confidence"], scam_score)

    if state["confidence"] >= 0.3:
        state["active"] = True

    intel = extract_intel(msg)

    reply = (
        "I’m worried about my account. Can you explain what I need to do?"
        if state["active"]
        else "Okay, can you share more details?"
    )

    duration = int((datetime.utcnow() - state["start_time"]).total_seconds())

    return HoneypotResponse(
        conversation_id=cid,
        scam_detected=state["active"],
        confidence_score=round(state["confidence"], 2),
        agent_active=state["active"],
        engagement_metrics=EngagementMetrics(
            turn_count=state["turns"],
            engagement_duration_sec=duration
        ),
        extracted_intelligence=ExtractedIntelligence(
            upi_ids=intel["upi_ids"],
            bank_accounts=[],
            phishing_urls=intel["phishing_urls"]
        ),
        agent_reply=reply
    )
