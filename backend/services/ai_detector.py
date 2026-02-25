import os
import re
import json
import whois
import tldextract
from datetime import datetime
from urlextract import URLExtract
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY", "ollama"),
    base_url=os.getenv("OPENAI_API_BASE", "http://localhost:11434/v1")
)

# Constants for Layer 1
SUSPICIOUS_TLDS = ['.ru', '.xyz', '.top', '.click', '.su', '.cn']
SHORTENERS = ['bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly']
URGENCY_KEYWORDS = ['urgent', 'immediately', 'password reset', 'invoice overdue', 'action required', 'account suspended']
MAJOR_BRANDS = ['microsoft', 'google', 'apple', 'amazon', 'paypal', 'netflix', 'facebook']

def extract_urls(text: str) -> list:
    extractor = URLExtract()
    return extractor.find_urls(text)

def layer1_heuristics(text: str, urls: list) -> tuple:
    score = 0
    features = {
        "urgency_score": 0,
        "typosquatting": False,
        "raw_ip_url": False,
        "shortened_url": False,
        "suspicious_tld": False,
        "base64_obfuscation": False
    }

    text_lower = text.lower()
    for kw in URGENCY_KEYWORDS:
        if kw in text_lower:
            features["urgency_score"] += 2
            score += 15

    if re.search(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', text):
        features["base64_obfuscation"] = True
        score += 20

    for url in urls:
        ext = tldextract.extract(url)
        domain = ext.domain.lower()
        tld = f".{ext.suffix.lower()}"

        if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', domain):
            features["raw_ip_url"] = True
            score += 30

        if f"{domain}{tld}" in SHORTENERS:
            features["shortened_url"] = True
            score += 20

        if tld in SUSPICIOUS_TLDS:
            features["suspicious_tld"] = True
            score += 25

        for brand in MAJOR_BRANDS:
            if domain != brand and len(domain) > 3:
                if brand in domain:
                     features["typosquatting"] = True
                     score += 30

    return min(score, 100), features

def layer2_auth_check(metadata: dict) -> tuple:
    score = 0
    spf_fail = metadata.get("spf", "pass").lower() != "pass"
    dkim_fail = metadata.get("dkim", "pass").lower() != "pass"
    
    if spf_fail: score += 20
    if dkim_fail: score += 20
    
    return min(score, 100), {"spf_fail": spf_fail, "dkim_fail": dkim_fail}

def layer3_domain_intel(urls: list) -> tuple:
    score = 0
    features = {"domain_age_days": -1}
    if not urls:
        return 0, features
    
    try:
        ext = tldextract.extract(urls[0])
        domain_to_check = f"{ext.domain}.{ext.suffix}"
        
        w = whois.whois(domain_to_check)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            features["domain_age_days"] = age_days
            if age_days < 30:
                score += 30
    except Exception:
        pass

    return min(score, 100), features

def analyze_email_hybrid(email_text: str, metadata: dict | None = None, user_context: dict | None = None) -> dict:
    if metadata is None:
        metadata = {}
    if user_context is None:
        user_context = {"role": "Unknown", "behavioral_risk_score": 0, "failed_simulations_count": 0, "typical_topics": "Anything"}
        
    urls = extract_urls(email_text)
    
    h_score, h_features = layer1_heuristics(email_text, urls)
    a_score, a_features = layer2_auth_check(metadata)
    d_score, d_features = layer3_domain_intel(urls)
    
    features = {**h_features, **a_features, **d_features, "user_behavioral_risk": user_context.get("behavioral_risk_score", 0), "failed_simulations_count": user_context.get("failed_simulations_count", 0)}
    
    safe_text = str(email_text)
    prompt = f"""
    You are a senior SOC analyst evaluating a potential spear-phishing email.
    
    Victim Context (Target User):
    - Role/Department: {user_context.get("role", "Unknown")}
    - Typical Work Topics: {user_context.get("typical_topics", "Unknown")}
    - Historical Risk Score: {user_context.get("behavioral_risk_score", 0)}/100
    
    Based on the technical features below:
    {json.dumps(features, indent=2)}
    
    Email Text Snippet:
    {safe_text[:500]}
    
    Calculate final LLM phishing probability (0-100).
    Explain reasoning shortly.
    Classify threat type (e.g., Credential Harvesting, Spam, Malware, Safe).
    
    Return ONLY JSON:
    {{
      "llm_score": 0,
      "explanation": "...",
      "threat_type": "..."
    }}
    """
    
    llm_score = 0
    explanation = "Error analyzing with AI."
    threat_type = "Unknown"
    
    try:
        response = client.chat.completions.create(
            model=os.getenv("AI_MODEL", "phi3"),
            messages=[{"role": "user", "content": prompt}],
            response_format={ "type": "json_object" }
        )
        llm_result = json.loads(response.choices[0].message.content)
        llm_score = llm_result.get("llm_score", 0)
        explanation = llm_result.get("explanation", "No explanation.")
        threat_type = llm_result.get("threat_type", "Unknown")
    except Exception as e:
         print(f"LLM Error: {e}")
         
    behavioral_risk = user_context.get("behavioral_risk_score", 0)
    
    # New Final Score formula integrating behavioral risk
    # FinalScore = Heuristics(30%) + Auth(15%) + Domain(15%) + BehavioralRisk(20%) + LLM(20%)
    final_score = int((h_score * 0.3) + (a_score * 0.15) + (d_score * 0.15) + (behavioral_risk * 0.2) + (llm_score * 0.2))
    
    return {
        "final_risk_score": final_score,
        "heuristic_score": h_score,
        "auth_score": a_score,
        "domain_score": d_score,
        "llm_score": llm_score,
        "behavioral_risk_score": behavioral_risk,
        "explanation": explanation,
        "threat_type": threat_type,
        "features": features,
        "urls_found": urls
    }

def analyze_email_text(email_text: str) -> dict:
    """Fallback / simplified function for quick UI testing or backwards compatibility"""
    # Using default context
    res = analyze_email_hybrid(email_text)
    return {
        "phishing_score": res["final_risk_score"],
        "url_threat_score": res["heuristic_score"],
        "explanation": res["explanation"]
    }
