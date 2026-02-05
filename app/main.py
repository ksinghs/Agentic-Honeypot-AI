from fastapi import FastAPI, Depends
from app.schemas import *
from app.security import verify_api_key
import time, re

app = FastAPI()
memory = {}

UPI = re.compile(r"[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}")
URL = re.compile(r"https?://[^\s]+")
BANK = re.compile(r"\b\d{9,18}\b")

def extract(text):
    return {
        "upi": list(set(UPI.findall(text))),
        "url": list(set(URL.findall(text))),
        "bank": list(set(BANK.findall(text)))
    }

@app.post("/v1/message", response_model=ResponsePayload)
def receive(msg: IncomingMessage, _=Depends(verify_api_key)):
    mem = memory.setdefault(msg.conversation_id, {"start": time.time(), "turns": 0})
    mem["turns"] += 1

    text = msg.message.lower()
    scam = any(k in text for k in ["kyc","blocked","refund","verify","pay","upi","account"])

    reply = (
        "Okay, can you explain a bit more?"
        if not scam
        else "Alright, I want to resolve this. What details do you need from me?"
    )

    entities = extract(msg.message + " " + reply)

    intel = Intelligence(
        upi_ids=[Evidence(value=v, confidence=0.9) for v in entities["upi"]],
        bank_accounts=[Evidence(value=v, confidence=0.85) for v in entities["bank"]],
        phishing_urls=[Evidence(value=v, confidence=0.95) for v in entities["url"]]
    )

    confidence = 0.2
    if intel.upi_ids or intel.bank_accounts or intel.phishing_urls:
        confidence = 0.85

    return ResponsePayload(
        conversation_id=msg.conversation_id,
        scam_detected=scam,
        confidence_score=confidence,
        agent_active=scam,
        engagement_metrics=Metrics(
            turn_count=mem["turns"],
            engagement_duration_sec=int(time.time() - mem["start"])
        ),
        extracted_intelligence=intel,
        agent_reply=reply
    )
