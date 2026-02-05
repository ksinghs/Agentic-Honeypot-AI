from pydantic import BaseModel
from typing import List

class IncomingMessage(BaseModel):
    conversation_id: str
    message: str
    timestamp: str

class Evidence(BaseModel):
    value: str
    confidence: float

class Intelligence(BaseModel):
    upi_ids: List[Evidence] = []
    bank_accounts: List[Evidence] = []
    phishing_urls: List[Evidence] = []

class Metrics(BaseModel):
    turn_count: int
    engagement_duration_sec: int

class ResponsePayload(BaseModel):
    conversation_id: str
    scam_detected: bool
    confidence_score: float
    agent_active: bool
    engagement_metrics: Metrics
    extracted_intelligence: Intelligence
    agent_reply: str
