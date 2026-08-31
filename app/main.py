from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional

from app.detectors.file_detector import analyze_file_content
from app.detectors.url_detector import analyze_url_target
from app.detectors.apk_detector import analyze_apk_content

from app.ml.features.url import extract_url_features
from app.ml.features.file import extract_file_features
from app.ml.features.apk import extract_apk_features

from app.ml.classifiers.url_classifier import url_classifier
from app.ml.classifiers.file_classifier import file_classifier
from app.ml.classifiers.apk_classifier import apk_classifier

from app.ml.anomaly.anomaly_detector import (
    url_anomaly_detector,
    file_anomaly_detector,
    apk_anomaly_detector,
)

from app.ml.correlation.ioc_graph import build_ioc_relationship_graph
from app.ml.scoring.risk_engine import calculate_unified_risk
from app.ai.assistant import generate_grounded_ai_analysis, sanitize_untrusted_input

app = FastAPI(
    title="CyberShield Advanced AI + ML Detection Microservice",
    description="Multi-Vector Threat Detection with Supervised ML, Isolation Forest Anomaly Detection, IOC Graph Correlation, and Grounded AI Explainability.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UrlScanRequest(BaseModel):
    url: str

class AIChatRequest(BaseModel):
    query: str
    scanContext: Dict[str, Any]

@app.get("/")
def read_root():
    return {
        "service": "CyberShield AI+ML Threat Engine",
        "status": "online",
        "version": "2.0.0",
        "architecture": "Rule-Based + Supervised-ML + IsolationForest + IOC-Graph + Grounded-AI",
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "cybershield-analysis-engine",
        "engines": {
            "file_detector": "ready",
            "url_detector": "ready",
            "apk_detector": "ready",
            "ml_classifier": "ready",
            "anomaly_detector": "ready",
            "ioc_correlation": "ready",
            "ai_grounding": "ready",
        },
    }

@app.post("/analyze/url")
async def analyze_url_endpoint(payload: UrlScanRequest):
    raw_result = await analyze_url_target(payload.url)
    
    # 1. Feature Extraction
    features = extract_url_features(payload.url, raw_result.get("httpMetadata", {}))
    
    # 2. ML Classifier & Anomaly Detector
    ml_analysis = url_classifier.predict(features)
    anomaly_analysis = url_anomaly_detector.compute_anomaly(features)
    
    # 3. Rule Score
    rule_score = raw_result.get("riskScore", 0)
    indicators = raw_result.get("indicators", [])
    
    # 4. Multi-Signal Unified Risk Aggregation
    unified_risk = calculate_unified_risk(rule_score, ml_analysis, anomaly_analysis, indicators)
    
    # 5. IOC Relationship Graph
    ioc_graph = build_ioc_relationship_graph(
        target=payload.url,
        scan_type="URL",
        hostname=raw_result.get("hostname"),
        resolved_ips=raw_result.get("resolvedIPs", []),
    )
    
    # 6. Grounded AI Explanation & MITRE RAG
    ai_analysis = generate_grounded_ai_analysis(
        target=payload.url,
        scan_type="URL",
        verdict=unified_risk["verdict"],
        risk_score=unified_risk["riskScore"],
        indicators=indicators,
        ml_analysis=ml_analysis,
        anomaly_analysis=anomaly_analysis,
    )

    return {
        "target": payload.url,
        "scanType": "URL",
        "riskScore": unified_risk["riskScore"],
        "verdict": unified_risk["verdict"],
        "confidence": unified_risk["confidence"],
        "indicators": indicators,
        "explanation": raw_result.get("explanation", []),
        "mlAnalysis": ml_analysis,
        "anomalyAnalysis": anomaly_analysis,
        "iocGraph": ioc_graph,
        "aiAnalysis": ai_analysis,
        "metadata": {
            "hostname": raw_result.get("hostname"),
            "resolvedIPs": raw_result.get("resolvedIPs", []),
            "entropy": raw_result.get("entropy", 0.0),
            "httpMetadata": raw_result.get("httpMetadata", {}),
            "features": features,
        },
    }

@app.post("/analyze/file")
async def analyze_file_endpoint(file: UploadFile = File(...)):
    content = await file.read()
    raw_result = analyze_file_content(file.filename or "unknown.bin", content)
    
    metadata = raw_result.get("metadata", {})
    indicators = raw_result.get("indicators", [])
    has_double_ext = any(i.get("id") == "FILE-001" for i in indicators)
    
    # 1. Feature Extraction
    features = extract_file_features(
        file_size=len(content),
        entropy=raw_result.get("entropy", 0.0),
        indicators_count=len(indicators),
        discovered_ips_count=len(metadata.get("discoveredIPs", [])),
        discovered_urls_count=len(metadata.get("discoveredURLs", [])),
        has_double_ext=has_double_ext,
        pe_details=metadata.get("peDetails", {}),
    )
    
    # 2. ML Classifier & Anomaly Detector
    ml_analysis = file_classifier.predict(features)
    anomaly_analysis = file_anomaly_detector.compute_anomaly(features)
    
    # 3. Rule Score & Risk Aggregation
    rule_score = raw_result.get("riskScore", 0)
    unified_risk = calculate_unified_risk(rule_score, ml_analysis, anomaly_analysis, indicators)
    
    # 4. IOC Relationship Graph
    ioc_graph = build_ioc_relationship_graph(
        target=file.filename or "unknown.bin",
        scan_type="FILE",
        sha256=raw_result.get("sha256"),
        discovered_ips=metadata.get("discoveredIPs", []),
        discovered_urls=metadata.get("discoveredURLs", []),
    )
    
    # 5. Grounded AI Explanation & MITRE RAG
    ai_analysis = generate_grounded_ai_analysis(
        target=file.filename or "unknown.bin",
        scan_type="FILE",
        verdict=unified_risk["verdict"],
        risk_score=unified_risk["riskScore"],
        indicators=indicators,
        ml_analysis=ml_analysis,
        anomaly_analysis=anomaly_analysis,
    )

    return {
        "target": file.filename or "unknown.bin",
        "scanType": "FILE",
        "sha256": raw_result.get("sha256"),
        "hashes": raw_result.get("hashes", {}),
        "fileSize": len(content),
        "mimeType": raw_result.get("detectedType", "Binary / Unknown"),
        "riskScore": unified_risk["riskScore"],
        "verdict": unified_risk["verdict"],
        "confidence": unified_risk["confidence"],
        "indicators": indicators,
        "explanation": raw_result.get("explanation", []),
        "mlAnalysis": ml_analysis,
        "anomalyAnalysis": anomaly_analysis,
        "iocGraph": ioc_graph,
        "aiAnalysis": ai_analysis,
        "metadata": {
            "detectedType": raw_result.get("detectedType"),
            "discoveredIPs": metadata.get("discoveredIPs", []),
            "discoveredURLs": metadata.get("discoveredURLs", []),
            "peDetails": metadata.get("peDetails", {}),
            "features": features,
        },
    }

@app.post("/analyze/apk")
async def analyze_apk_endpoint(file: UploadFile = File(...)):
    content = await file.read()
    raw_result = analyze_apk_content(file.filename or "sample.apk", content)
    
    metadata = raw_result.get("metadata", {})
    indicators = raw_result.get("indicators", [])
    
    # 1. Feature Extraction
    features = extract_apk_features(metadata, indicators)
    
    # 2. ML Classifier & Anomaly Detector
    ml_analysis = apk_classifier.predict(features)
    anomaly_analysis = apk_anomaly_detector.compute_anomaly(features)
    
    # 3. Rule Score & Risk Aggregation
    rule_score = raw_result.get("riskScore", 0)
    unified_risk = calculate_unified_risk(rule_score, ml_analysis, anomaly_analysis, indicators)
    
    # 4. IOC Relationship Graph
    ioc_graph = build_ioc_relationship_graph(
        target=file.filename or "sample.apk",
        scan_type="APK",
        sha256=raw_result.get("sha256"),
        package_name=metadata.get("packageName"),
        discovered_urls=metadata.get("discoveredURLs", []),
    )
    
    # 5. Grounded AI Explanation & MITRE RAG
    ai_analysis = generate_grounded_ai_analysis(
        target=file.filename or "sample.apk",
        scan_type="APK",
        verdict=unified_risk["verdict"],
        risk_score=unified_risk["riskScore"],
        indicators=indicators,
        ml_analysis=ml_analysis,
        anomaly_analysis=anomaly_analysis,
    )

    return {
        "target": file.filename or "sample.apk",
        "scanType": "APK",
        "sha256": raw_result.get("sha256"),
        "hashes": raw_result.get("hashes", {}),
        "fileSize": len(content),
        "mimeType": "application/vnd.android.package-archive",
        "riskScore": unified_risk["riskScore"],
        "verdict": unified_risk["verdict"],
        "confidence": unified_risk["confidence"],
        "indicators": indicators,
        "explanation": raw_result.get("explanation", []),
        "mlAnalysis": ml_analysis,
        "anomalyAnalysis": anomaly_analysis,
        "iocGraph": ioc_graph,
        "aiAnalysis": ai_analysis,
        "metadata": {
            **metadata,
            "features": features,
        },
    }

@app.post("/ai/assistant")
async def ai_assistant_chat(payload: AIChatRequest):
    query = sanitize_untrusted_input(payload.query).lower()
    ctx = payload.scanContext
    indicators = ctx.get("indicators", [])
    target = ctx.get("target", "Target")
    verdict = ctx.get("verdict", "UNKNOWN")
    score = ctx.get("riskScore", 0)
    ml = ctx.get("mlAnalysis", {})
    anomaly = ctx.get("anomalyAnalysis", {})
    ai = ctx.get("aiAnalysis", {})

    if "why" in query or "reason" in query or "risk" in query:
        response = (
            f"Target '{target}' was evaluated with a Risk Score of {score}/100 ({verdict}). "
            f"The Supervised ML classifier detected {int(ml.get('probability', 0) * 100)}% {ml.get('prediction', 'risk')} probability. "
            f"{len(indicators)} heuristic indicators were triggered, including: {', '.join([i.get('name', '') for i in indicators[:3]]) or 'baseline behavior'}."
        )
    elif "mitre" in query or "tactic" in query or "technique" in query:
        tactics = ai.get("mitreTactics", [])
        if tactics:
            tac_strs = [f"{t.get('techniqueId')} ({t.get('techniqueName')}) - Tactic: {t.get('tactic')}" for t in tactics]
            response = f"Relevant MITRE ATT&CK mappings identified for this target:\n• " + "\n• ".join(tac_strs)
        else:
            response = "No high-confidence MITRE ATT&CK techniques mapped to this specific clean sample."
    elif "recommend" in query or "action" in query or "fix" in query:
        recs = ai.get("recommendations", ["Monitor asset telemetry."])
        response = "Recommended SOC Actions:\n• " + "\n• ".join(recs)
    elif "ioc" in query or "graph" in query or "ip" in query:
        graph = ctx.get("iocGraph", {})
        nodes = graph.get("nodes", [])
        response = f"IOC Relationship graph contains {len(nodes)} identified entities across network and file artifacts."
    else:
        response = (
            f"CyberShield AI Assistant: Target '{target}' is classified as {verdict} (Score: {score}/100). "
            f"ML Model: {ml.get('model', 'Ensemble')} ({int(ml.get('probability', 0)*100)}% confidence). "
            f"Anomaly metric: {int(anomaly.get('anomalyScore', 0)*100)}% ({anomaly.get('status', 'NORMAL')})."
        )

    return {"response": response, "grounded": True}
