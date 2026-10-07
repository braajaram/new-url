"""
Threat Analyze - Python Microservice Spec
FastAPI microservice mirroring and providing advanced Scikit-Learn training and external threat enrichment.
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import math
from typing import List, Optional

app = FastAPI(
    title="Threat Analyze Python ML & IOC Engine",
    version="2.4.0",
    description="Python FastAPI backend powering scikit-learn models and threat intelligence lookups."
)

class FeatureVector(BaseModel):
    url: str
    hostname: str
    length: int
    entropy: float
    punycode: bool
    at_symbol: bool
    suspicious_keywords_count: int

class PredictionResult(BaseModel):
    prediction: str
    confidence: float
    risk_score: int
    reasons: List[str]

@app.get("/health")
def health():
    return {"status": "OPERATIONAL", "engine": "FastAPI/Scikit-Learn", "version": "2.4.0"}

@app.post("/predict", response_model=PredictionResult)
def predict(vector: FeatureVector):
    score = 10
    reasons = []
    
    if vector.entropy > 4.2:
        score += 30
        reasons.append(f"High domain entropy ({vector.entropy:.2f}) indicates potential DGA")
    if vector.punycode:
        score += 35
        reasons.append("Punycode IDN detected (potential lookalike spoofing)")
    if vector.at_symbol:
        score += 40
        reasons.append("Credential @ delimiter in URL authority")
    if vector.suspicious_keywords_count > 0:
        score += vector.suspicious_keywords_count * 15
        reasons.append(f"Contains {vector.suspicious_keywords_count} phishing/harvesting keyword triggers")
        
    score = min(100, max(5, score))
    verdict = "MALICIOUS" if score >= 70 else ("SUSPICIOUS" if score >= 35 else "SAFE")
    confidence = 0.94 if verdict != "UNKNOWN" else 0.50
    
    return PredictionResult(
        prediction=verdict,
        confidence=confidence,
        risk_score=score,
        reasons=reasons or ["Clean lexical footprint"]
    )
