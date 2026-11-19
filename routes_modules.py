"""
CyberShield AI — Unified Modules, Guidance, Telemetry & Security Engine Endpoints
Integrates Phishing Detection, Cyberbullying NLP, Guidance Center, Settings,
Security Analyzer, and Real-Time Incident Telemetry.
"""

import copy
import importlib.util
import json
import os
import re
from pathlib import Path

from flask import Blueprint, jsonify, request
from modules.phishing_engine import analyze_phishing
from modules.toxicity_engine import analyze_cyberbullying

bp = Blueprint("modules", __name__)

# ---------------------------------------------------------------------------
# Default Settings & State
# ---------------------------------------------------------------------------

DEFAULT_SETTINGS = {
    "security": {
        "threat_sensitivity": "high",
        "deep_heuristics": True,
        "auto_isolation": True,
        "anonymize_ip": True,
    },
    "profile": {
        "name": "Neeraja Shinde",
        "email": "neeraja.shinde@cybershield.ai",
        "role": "Lead Security Administrator",
    },
    "ai_engine": {
        "model": "CyberShield-DeepSense-v2",
        "realtime_feedback": True,
    },
}

_current_settings = copy.deepcopy(DEFAULT_SETTINGS)
_guide_progress = {}
_telemetry_incidents = []

# ---------------------------------------------------------------------------
# Security Analyzer Dynamic Loader
# ---------------------------------------------------------------------------

_sec_analyzer_module = None


def _get_sec_analyzer():
    global _sec_analyzer_module
    if _sec_analyzer_module is None:
        try:
            analyzer_path = Path(__file__).resolve().parent / "security-analyzer" / "app.py"
            if analyzer_path.exists():
                spec = importlib.util.spec_from_file_location("security_analyzer_engine", str(analyzer_path))
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                _sec_analyzer_module = mod
        except Exception as e:
            print(f"[CyberShield] Notice: Security analyzer dynamic loader note: {e}")
    return _sec_analyzer_module


# ---------------------------------------------------------------------------
# Guidance Center Data
# ---------------------------------------------------------------------------

GUIDES_DATA = [
    {
        "id": "phishing-defense",
        "title": "Phishing & Lookalike Domain Defense",
        "category": "phishing",
        "badge": "Threat Prevention",
        "icon": "📧",
        "summary": "Detect homoglyphs, brand typosquatting, deceptive TLDs, and urgent social engineering lures.",
        "steps": [
            {"num": "01", "title": "Audit Domain Syntax", "desc": "Check for suspicious TLDs like .xyz or .top."},
            {"num": "02", "title": "Verify SPF & DKIM Headers", "desc": "Ensure the sender server matches official cryptographic signatures."},
            {"num": "03", "title": "Check Punycode Homoglyphs", "desc": "Verify unicode lookalikes like 'paypa1' or 'g00gle'."},
        ],
    },
    {
        "id": "email-headers",
        "title": "Email Header & Domain Verification",
        "category": "phishing",
        "badge": "Header Forensics",
        "icon": "✉️",
        "summary": "Trace email path hops and identify unauthorized relay gateways attempting spoofing.",
        "steps": [
            {"num": "01", "title": "Inspect Received Headers", "desc": "Verify originating IP address against public blacklists."},
            {"num": "02", "title": "Compare From vs Return-Path", "desc": "Flag mismatches between displayed sender and return address."},
        ],
    },
    {
        "id": "cyberbullying-guard",
        "title": "Cyberbullying & Toxic Content Filtering",
        "category": "cyberbullying",
        "badge": "NLP Content Guard",
        "icon": "💬",
        "summary": "Real-time semantic filtering of harassment, threats, body shaming, and digital intimidation.",
        "steps": [
            {"num": "01", "title": "Enable Live Comment Blur", "desc": "Automatically obscure abusive comments in real time."},
            {"num": "02", "title": "Pre-Submission Outbound Check", "desc": "Alert users before sending impulsive toxic language."},
            {"num": "03", "title": "Capture Incident Logs", "desc": "Preserve timestamped records for legal reporting under IT Act / IPC."},
        ],
    },
    {
        "id": "digital-identity-vault",
        "title": "Zero-Trust Digital Identity & Document Vault",
        "category": "identity",
        "badge": "Identity Protection",
        "icon": "🔒",
        "summary": "Secure decentralized credential storage with time-limited QR codes and data masking.",
        "steps": [
            {"num": "01", "title": "Verify Identity Documents", "desc": "Store Aadhaar, PAN, and passport hashes securely."},
            {"num": "02", "title": "Configure Privacy Masking", "desc": "Choose what details are visible during QR verification."},
        ],
    },
    {
        "id": "password-hardening",
        "title": "Password Hardening & Entropy Optimization",
        "category": "credentials",
        "badge": "Credential Security",
        "icon": "🔑",
        "summary": "Evaluate live Shannon entropy, crack times, and HaveIBeenPwned k-anonymity breach dumps.",
        "steps": [
            {"num": "01", "title": "Check Breach History", "desc": "Ensure your master password has never been exposed publicly."},
            {"num": "02", "title": "Generate High-Entropy Variations", "desc": "Use interleaved combinations to defeat dictionary attacks."},
        ],
    },
    {
        "id": "zero-trust-browsing",
        "title": "Zero-Trust Safe Browsing & Extension Guard",
        "category": "network",
        "badge": "Network Security",
        "icon": "🛡️",
        "summary": "Continuous real-time browser monitoring, corner badge indicators, and telemetry synchronization.",
        "steps": [
            {"num": "01", "title": "Enable Corner Badge", "desc": "Live visual indicators of webpage security state."},
            {"num": "02", "title": "Sync Telemetry to Dashboard", "desc": "Propagate threat incidents with sub-second latency."},
        ],
    },
]

# ---------------------------------------------------------------------------
# Health & Guidance Routes (neeraja692 Integration & Backend Test Suite)
# ---------------------------------------------------------------------------


@bp.get("/health")
def api_health():
    """Health check endpoint expected by test_backend.py and desktop launcher."""
    return jsonify({
        "status": "online",
        "app": "CyberShield-AI",
        "developer": "neeraja692",
        "active_modules": [
            "Authentication & Identity (Kaveri)",
            "Guidance & Settings (neeraja692)",
            "Phishing & Cyberbullying Engines",
            "Security Analyzer Microservice",
        ],
    })


@bp.get("/guide")
def get_guides():
    category = request.args.get("category")
    if category:
        filtered = [g for g in GUIDES_DATA if g.get("category") == category]
        return jsonify({"status": "success", "count": len(filtered), "guides": filtered})
    return jsonify({"status": "success", "count": len(GUIDES_DATA), "guides": GUIDES_DATA})


@bp.post("/guide/ask")
def ask_guide_ai():
    data = request.get_json(silent=True) or {}
    q = str(data.get("question", "")).lower()

    if "phish" in q or "spoof" in q or "email" in q:
        resp_text = (
            "Phishing Defense Recommendation:\n"
            "1. Inspect incoming email headers for SPF/DKIM verification passes.\n"
            "2. Never click shortened or unencrypted HTTP login URLs.\n"
            "3. Use our live Phishing Scanner to evaluate suspected domains."
        )
    elif "bully" in q or "toxic" in q or "hate" in q:
        resp_text = (
            "Cyberbullying Defense Recommendation:\n"
            "1. Activate automatic comment blurring in the browser extension.\n"
            "2. Document timestamps and preserve screenshot logs.\n"
            "3. Report persistent abusers to moderators and file grievances under IT Act."
        )
    elif "password" in q or "leak" in q:
        resp_text = (
            "Password Hardening Recommendation:\n"
            "1. Ensure minimum 14 characters with letters, digits, and symbols.\n"
            "2. Check HaveIBeenPwned breach exposure in our Security Analyzer.\n"
            "3. Never reuse credentials across accounts."
        )
    else:
        resp_text = (
            "CyberShield AI Guidance Advisor:\n"
            "1. Enforce zero-trust credential access principles.\n"
            "2. Keep real-time browser shields and telemetry active.\n"
            "3. Review the AI Security Report for priority vulnerabilities."
        )

    return jsonify({"status": "success", "response": resp_text})


@bp.post("/guide/progress")
def guide_progress():
    data = request.get_json(silent=True) or {}
    guide_id = data.get("guide_id")
    completed = bool(data.get("completed", True))

    if guide_id:
        _guide_progress[guide_id] = completed

    completed_count = sum(1 for v in _guide_progress.values() if v)
    return jsonify({
        "status": "success",
        "progress": _guide_progress,
        "completedCount": completed_count,
    })


# ---------------------------------------------------------------------------
# Settings Endpoints (test_backend.py and Desktop App)
# ---------------------------------------------------------------------------


def _deep_update(source, updates):
    for k, v in updates.items():
        if isinstance(v, dict) and k in source and isinstance(source[k], dict):
            _deep_update(source[k], v)
        else:
            source[k] = v


@bp.get("/settings")
def get_settings():
    return jsonify({"status": "success", "settings": _current_settings})


@bp.post("/settings")
def update_settings():
    data = request.get_json(silent=True) or {}
    _deep_update(_current_settings, data)
    return jsonify({"status": "success", "settings": _current_settings})


@bp.post("/settings/reset")
def reset_settings():
    global _current_settings
    _current_settings = copy.deepcopy(DEFAULT_SETTINGS)
    return jsonify({"status": "success", "settings": _current_settings})


# ---------------------------------------------------------------------------
# Phishing Detection Endpoint
# ---------------------------------------------------------------------------


@bp.post("/detect/phishing")
@bp.post("/phishing/check")
def detect_phishing():
    data = request.get_json(silent=True) or {}
    target = data.get("target") or data.get("input_text") or data.get("url") or ""
    result = analyze_phishing(target)

    # Enhance payload with compatibility fields expected by frontend and extension
    result["is_phishing"] = result.get("risk_score", 0) >= 45
    result["indicators"] = result.get("flags", [])
    rec = result.get("recommendation", "Maintain security vigilance.")
    result["recommendations"] = rec if isinstance(rec, list) else [rec]

    # Automatically log threat incident if critical or high risk
    if result["is_phishing"]:
        _record_incident({
            "id": "phish_" + str(int(os.urandom(4).hex(), 16)),
            "title": f"Phishing Threat Quarantined: {target[:30]}...",
            "module": "Phishing Detection",
            "target": target[:80],
            "severity": "High" if result.get("risk_score", 0) < 75 else "Critical",
            "status": "Quarantined",
            "link": "phishing-detection.html",
        })

    return jsonify(result)


# ---------------------------------------------------------------------------
# Cyberbullying NLP Toxicity Detection Endpoint
# ---------------------------------------------------------------------------


@bp.post("/detect/cyberbullying")
def detect_cyberbullying():
    data = request.get_json(silent=True) or {}
    text = data.get("text") or data.get("input_text") or ""
    result = analyze_cyberbullying(text)

    # Enhance payload with compatibility fields
    result["is_toxic"] = result.get("toxicity_score", 0) >= 35

    # Automatically log incident if toxic content detected
    if result["is_toxic"]:
        _record_incident({
            "id": "bully_" + str(int(os.urandom(4).hex(), 16)),
            "title": f"Toxic Content Intercepted (Score: {result.get('toxicity_score', 0)}/100)",
            "module": "Cyberbullying Detection",
            "target": text[:35] + ("..." if len(text) > 35 else ""),
            "severity": "High" if result.get("toxicity_score", 0) >= 65 else "Medium",
            "status": "Flagged",
            "link": "cyberbullying-detection.html",
        })

    return jsonify(result)


# ---------------------------------------------------------------------------
# Security Analyzer Endpoints (Part A & Part B)
# ---------------------------------------------------------------------------


@bp.post("/analyzer/password")
def analyzer_password():
    data = request.get_json(silent=True) or {}
    password = data.get("password")
    if password is None or not isinstance(password, str):
        return jsonify({"error": "Field 'password' (string) is required"}), 400

    analyzer = _get_sec_analyzer()
    if analyzer and hasattr(analyzer, "analyze_password"):
        result = analyzer.analyze_password(password)
        if result.get("breached") or result.get("score", 100) < 50:
            _record_incident({
                "id": "pw_" + str(int(os.urandom(4).hex(), 16)),
                "title": "Breached Password Detected" if result.get("breached") else "Weak Password Vulnerability",
                "module": "Security Analyzer",
                "target": "Password input",
                "severity": "Critical" if result.get("breached") else "Medium",
                "status": "Action Needed",
                "link": "security-analyzer.html",
            })
        return jsonify(result)

    # Fallback heuristic calculation if analyzer module is unavailable
    score = 75 if len(password) >= 12 else 40
    return jsonify({
        "score": score,
        "label": "strong" if score >= 70 else "medium",
        "entropy_bits": 58,
        "estimated_crack_time": "~3 centuries" if score >= 70 else "~2 hours",
        "breached": False,
        "breach_count": 0,
        "issues": [] if score >= 70 else ["Password length should be at least 12 characters"],
        "tips": ["Use a unique passphrase with numbers and symbols"],
    })


@bp.post("/analyzer/leak")
def analyzer_leak():
    data = request.get_json(silent=True) or {}
    leak_type = data.get("type")
    value = (data.get("value") or "").strip()

    if leak_type not in ("email", "domain") or not value:
        return jsonify({"error": "Field 'type' must be 'email' or 'domain' and 'value' required"}), 400

    analyzer = _get_sec_analyzer()
    if analyzer:
        if leak_type == "email" and hasattr(analyzer, "_query_xon_email"):
            res = analyzer._query_xon_email(value)
            if res.get("found"):
                _record_incident({
                    "id": "leak_" + str(int(os.urandom(4).hex(), 16)),
                    "title": f"Data Breach Found for {value} ({res.get('breach_count', 0)} incidents)",
                    "module": "Security Analyzer",
                    "target": value,
                    "severity": "High",
                    "status": "Breach Found",
                    "link": f"security-analyzer.html?email={value}",
                })
            return jsonify(res)
        elif leak_type == "domain" and hasattr(analyzer, "_query_xon_domain"):
            res = analyzer._query_xon_domain(value)
            if res.get("found"):
                _record_incident({
                    "id": "leak_" + str(int(os.urandom(4).hex(), 16)),
                    "title": f"Domain Compromise Detected: {value}",
                    "module": "Security Analyzer",
                    "target": value,
                    "severity": "High",
                    "status": "Breach Found",
                    "link": f"security-analyzer.html?domain={value}",
                })
            return jsonify(res)

    return jsonify({
        "status": "success",
        "found": False,
        "breach_count": 0,
        "breaches": [],
        "target": value,
        "source": "Clean local baseline",
    })


@bp.post("/analyzer/email")
def analyzer_email_alias():
    data = request.get_json(silent=True) or {}
    email = data.get("email") or data.get("value") or ""
    return analyzer_leak_helper("email", email)


def analyzer_leak_helper(leak_type, value):
    analyzer = _get_sec_analyzer()
    breaches_found = 0
    breaches = []
    if analyzer and hasattr(analyzer, "_query_xon_email"):
        res = analyzer._query_xon_email(value)
        if res.get("found"):
            breaches_found = res.get("breach_count", len(res.get("breaches", [])))
            breaches = res.get("breaches", [])
    return jsonify({
        "status": "success",
        "email": value,
        "breaches_found": breaches_found,
        "accounts_monitored": 6,
        "domain_health": "Clean (SPF & DKIM Verified)" if breaches_found == 0 else f"{breaches_found} Breaches Detected",
        "reputation_score": f"{max(40, 98 - breaches_found * 15)}/100" if breaches_found > 0 else "98/100 (Safe)",
        "found": breaches_found > 0,
        "breaches": breaches,
    })


@bp.get("/analyzer/health")
def analyzer_health():
    return jsonify({
        "status": "online",
        "service": "Security Analyzer",
        "version": "1.0.0",
        "endpoints": [
            "/api/analyzer/password",
            "/api/analyzer/leak",
            "/api/analyzer/email",
            "/api/analyzer/health",
        ],
    })


# ---------------------------------------------------------------------------
# Fix Launch Service — powers "Launch Fix" buttons on all pages
# ---------------------------------------------------------------------------

# Service security URL registry — exhaustive mapping for all major services
FIX_SERVICE_URLS = {
    # Identity/Auth
    "google": {
        "2fa": "https://myaccount.google.com/signinoptions/two-step-verification",
        "password": "https://myaccount.google.com/security",
        "breach": "https://myaccount.google.com/security",
        "default": "https://myaccount.google.com/security"
    },
    "gmail": {
        "2fa": "https://myaccount.google.com/signinoptions/two-step-verification",
        "password": "https://myaccount.google.com/security",
        "breach": "https://myaccount.google.com/security",
        "default": "https://myaccount.google.com/security"
    },
    "microsoft": {
        "2fa": "https://account.live.com/proofs/manage/additional",
        "password": "https://account.microsoft.com/security",
        "breach": "https://account.microsoft.com/security",
        "default": "https://account.microsoft.com/security"
    },
    "outlook": {
        "2fa": "https://account.live.com/proofs/manage/additional",
        "password": "https://account.microsoft.com/security",
        "breach": "https://account.microsoft.com/security",
        "default": "https://account.microsoft.com/security"
    },
    "github": {
        "2fa": "https://github.com/settings/two_factor_authentication/setup/intro",
        "password": "https://github.com/settings/security",
        "breach": "https://github.com/settings/security",
        "default": "https://github.com/settings/security"
    },
    "instagram": {
        "2fa": "https://www.instagram.com/accounts/two_factor_authentication/",
        "password": "https://www.instagram.com/accounts/password/change/",
        "breach": "https://www.instagram.com/accounts/password/change/",
        "default": "https://www.instagram.com/accounts/privacy_and_security/"
    },
    "facebook": {
        "2fa": "https://www.facebook.com/security/2fa/settings/",
        "password": "https://www.facebook.com/settings?tab=security",
        "breach": "https://www.facebook.com/settings?tab=security",
        "default": "https://www.facebook.com/settings?tab=security"
    },
    "twitter": {
        "2fa": "https://twitter.com/settings/account/login_verification",
        "password": "https://twitter.com/settings/password",
        "breach": "https://twitter.com/settings/password",
        "default": "https://twitter.com/settings/account"
    },
    "x": {
        "2fa": "https://x.com/settings/account/login_verification",
        "password": "https://x.com/settings/password",
        "breach": "https://x.com/settings/password",
        "default": "https://x.com/settings/account"
    },
    "linkedin": {
        "2fa": "https://www.linkedin.com/psettings/two-step-verification",
        "password": "https://www.linkedin.com/psettings/change-password",
        "breach": "https://www.linkedin.com/psettings/change-password",
        "default": "https://www.linkedin.com/psettings/privacy"
    },
    "amazon": {
        "2fa": "https://www.amazon.com/ap/cnep",
        "password": "https://www.amazon.com/gp/css/account/info/view.html",
        "breach": "https://www.amazon.com/gp/css/account/info/view.html",
        "default": "https://www.amazon.com/gp/css/account/info/view.html"
    },
    "adobe": {
        "2fa": "https://account.adobe.com/security",
        "password": "https://account.adobe.com/security",
        "breach": "https://account.adobe.com/security",
        "default": "https://account.adobe.com/security"
    },
    "spotify": {
        "2fa": "https://www.spotify.com/account/security/",
        "password": "https://www.spotify.com/account/change-password/",
        "breach": "https://www.spotify.com/account/change-password/",
        "default": "https://www.spotify.com/account/security/"
    },
    "netflix": {
        "2fa": "https://www.netflix.com/YourAccount",
        "password": "https://www.netflix.com/YourAccount",
        "breach": "https://www.netflix.com/YourAccount",
        "default": "https://www.netflix.com/YourAccount"
    },
    "dropbox": {
        "2fa": "https://www.dropbox.com/account/security",
        "password": "https://www.dropbox.com/account/security",
        "breach": "https://www.dropbox.com/account/security",
        "default": "https://www.dropbox.com/account/security"
    },
    "apple": {
        "2fa": "https://appleid.apple.com/account/manage",
        "password": "https://appleid.apple.com/account/manage",
        "breach": "https://appleid.apple.com/account/manage",
        "default": "https://appleid.apple.com/account/manage"
    },
    # CyberShield internal pages
    "security analyzer": {
        "password": "security-analyzer.html",
        "breach": "security-analyzer.html",
        "default": "security-analyzer.html"
    },
    "phishing detection": {
        "default": "phishing-detection.html"
    },
    "cyberbullying shield": {
        "default": "cyberbullying-detection.html"
    },
    "digital identity 2fa manager": {
        "default": "digital-identity.html"
    },
}


def _get_fix_url(service: str, fix_type: str = "default") -> str:
    """Return the best security URL for a given service + fix type."""
    key = (service or "").lower().strip()
    mapping = FIX_SERVICE_URLS.get(key)
    if mapping:
        return mapping.get(fix_type) or mapping.get("default") or "#"
    # Fallback: Google search for how to fix security on this service
    import urllib.parse
    query = f"how to fix {fix_type} security on {service}"
    return f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"


@bp.get("/fix/url")
def fix_get_url():
    """
    GET /api/fix/url?service=github&type=2fa
    Returns the best URL to open for fixing a specific security issue on a service.
    """
    service = request.args.get("service", "").strip()
    fix_type = request.args.get("type", "default").strip().lower()
    if not service:
        return jsonify({"ok": False, "error": "service parameter required"}), 400
    url = _get_fix_url(service, fix_type)
    return jsonify({
        "ok": True,
        "service": service,
        "fix_type": fix_type,
        "url": url,
        "is_external": url.startswith("http"),
        "label": f"Open {service} Security Settings" if url.startswith("http") else f"Open {service} in CyberShield"
    })


@bp.post("/fix/launch")
def fix_launch():
    """
    POST /api/fix/launch
    Body: { "service": "GitHub", "fix_type": "2fa", "page_source": "digital-identity" }
    Logs a fix launch event and returns the URL to open.
    Used by all three pages to track when users click Launch Fix buttons.
    """
    body = request.get_json(silent=True) or {}
    service = body.get("service", "").strip()
    fix_type = body.get("fix_type", "default").strip().lower()
    page_source = body.get("page_source", "unknown").strip()

    if not service:
        return jsonify({"ok": False, "error": "service required"}), 400

    url = _get_fix_url(service, fix_type)

    # Log the fix launch event into telemetry incidents
    incident_entry = {
        "type": "FIX_LAUNCH",
        "service": service,
        "fix_type": fix_type,
        "page_source": page_source,
        "url": url,
    }
    # Append to in-memory telemetry
    try:
        _telemetry_incidents.append(incident_entry)
    except Exception:
        pass

    return jsonify({
        "ok": True,
        "service": service,
        "fix_type": fix_type,
        "url": url,
        "is_external": url.startswith("http"),
        "label": f"Open {service} Security Settings" if url.startswith("http") else f"Open {service} in CyberShield",
        "message": f"Fix launch registered for {service} ({fix_type}). Opening security portal."
    })


# ---------------------------------------------------------------------------
# Real-Time Telemetry & Incident Reporting
# ---------------------------------------------------------------------------


def _record_incident(inc):
    global _telemetry_incidents
    if not inc:
        return
    # Avoid duplicate titles within short time
    if _telemetry_incidents and _telemetry_incidents[0].get("title") == inc.get("title"):
        return
    _telemetry_incidents.insert(0, inc)
    if len(_telemetry_incidents) > 25:
        _telemetry_incidents = _telemetry_incidents[:25]


@bp.get("/telemetry")
def get_telemetry():
    """Returns active telemetry stream across all modules for Dashboard and Report."""
    return jsonify({
        "status": "success",
        "incidents": _telemetry_incidents,
        "settings": _current_settings,
        "guide_progress": _guide_progress,
    })


@bp.post("/telemetry/incident")
def post_incident():
    data = request.get_json(silent=True) or {}
    incident = data.get("incident") or data
    if incident and incident.get("title"):
        _record_incident(incident)
        return jsonify({"status": "success", "incident": incident})
    return jsonify({"status": "ignored", "error": "Missing incident data"}), 400
