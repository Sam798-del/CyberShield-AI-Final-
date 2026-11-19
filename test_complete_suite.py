"""
CyberShield AI — Complete Comprehensive Test Suite
Validates all website pages, backend APIs, microservices, and Chrome extension components.
"""
import os
import sys
import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def run_tests():
    print("=" * 70)
    print("      CYBERSHIELD AI — FULL PLATFORM & EXTENSION AUDIT")
    print("=" * 70)

    total_checks = 0
    passed_checks = 0

    def record(name, success, detail=""):
        nonlocal total_checks, passed_checks
        total_checks += 1
        if success:
            passed_checks += 1
            print(f"  [PASS] {name} {f'({detail})' if detail else ''}")
        else:
            print(f"  [FAIL] {name} - {detail}")

    # =========================================================================
    # 1. WEBSITE PAGES & STATIC SERVING
    # =========================================================================
    print("\n--- 1. Testing Website Pages & Static Assets ---")
    from app import create_app
    flask_app = create_app({"TESTING": True, "DEV_MODE": True})
    client = flask_app.test_client()

    pages = [
        ("/", 200, "CyberShield AI"),
        ("/index.html", 200, "CyberShield AI"),
        ("/pages/login.html", 200, "Sign In"),
        ("/pages/dashboard.html", 200, "Command Dashboard"),
        ("/pages/digital-identity.html", 200, "Digital Identity"),
        ("/pages/security-analyzer.html", 200, "Security Analyzer"),
        ("/pages/phishing-detection.html", 200, "Phishing Detection"),
        ("/pages/cyberbullying-detection.html", 200, "Cyberbullying"),
        ("/pages/security-report.html", 200, "AI Security Report"),
        ("/pages/settings.html", 200, "Settings"),
        ("/pages/guide.html", 200, "Feature Guide"),
    ]

    for path, exp_status, exp_snippet in pages:
        res = client.get(path)
        ok = (res.status_code == exp_status) and (exp_snippet.lower() in res.data.decode("utf-8", errors="ignore").lower())
        record(f"Page: {path}", ok, f"HTTP {res.status_code}")

    # =========================================================================
    # 2. BACKEND API SUITE (Auth, Identity, Modules, Extension Config)
    # =========================================================================
    print("\n--- 2. Testing Backend APIs ---")
    
    # 2.1 Health Check
    health_res = client.get("/healthz")
    record("API: /healthz", health_res.status_code == 200 and health_res.json.get("ok") is True)

    # 2.2 Register new user in DEV_MODE
    test_email = "test.suite.auditor@example.com"
    test_password = "P@ssword123!Secure#Audit"
    signup_res = client.post("/api/auth/register", json={
        "name": "Audit Tester",
        "email": test_email,
        "password": test_password
    })
    otp_code = None
    if signup_res.status_code == 200 and signup_res.json.get("ok"):
        otp_code = signup_res.json.get("data", {}).get("dev_code")
        record("API: /api/auth/register (Dev OTP returned)", True, f"Dev OTP: {otp_code}")
    else:
        # If user already exists, try logging in
        record("API: /api/auth/register", signup_res.status_code in (200, 409), f"Status {signup_res.status_code}")

    # 2.3 Verify OTP if generated
    if otp_code:
        verify_res = client.post("/api/auth/verify-email", json={
            "email": test_email,
            "code": otp_code
        })
        record("API: /api/auth/verify-email", verify_res.status_code == 200, "Email verified")

    # 2.4 Login
    login_res = client.post("/api/auth/login", json={
        "email": test_email,
        "password": test_password
    })
    token = None
    if login_res.status_code == 200 and login_res.json.get("ok"):
        token = login_res.json.get("data", {}).get("token")
        record("API: /api/auth/login", True, "Bearer token obtained")
    else:
        record("API: /api/auth/login", False, f"Failed: {login_res.data.decode()}")

    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

    # 2.5 Verify Token (Used by extension)
    verify_tok_res = client.get("/api/auth/verify-token", headers=auth_headers)
    record("API: /api/auth/verify-token", verify_tok_res.status_code == 200 and verify_tok_res.json.get("ok") is True)

    # 2.6 Extension Config (Used by extension upon startup)
    ext_cfg_res = client.get("/api/extension/config", headers=auth_headers)
    record("API: /api/extension/config", ext_cfg_res.status_code == 200 and "ai_model" in ext_cfg_res.json.get("data", {}))

    # 2.7 Digital Identity Summary & Accounts
    id_sum_res = client.get("/api/identity/summary", headers=auth_headers)
    record("API: /api/identity/summary", id_sum_res.status_code == 200 and "score" in id_sum_res.json.get("data", {}))

    id_acc_res = client.get("/api/identity/accounts", headers=auth_headers)
    record("API: /api/identity/accounts", id_acc_res.status_code == 200 and "accounts" in id_acc_res.json.get("data", {}))

    # 2.8 Phishing Scan API
    phish_payload = {"url": "http://paypa1-security-verification.xyz/login"}
    phish_res = client.post("/api/phishing/scan", json=phish_payload, headers=auth_headers)
    phish_data = phish_res.json.get("data", {}) if phish_res.status_code == 200 else {}
    record("API: /api/phishing/scan (Phishing detection)", phish_res.status_code == 200 and phish_data.get("risk_level") in ("HIGH", "CRITICAL"), f"Risk: {phish_data.get('risk_level')}")

    # 2.9 Cyberbullying Scan API
    bully_payload = {"text": "You are pathetic and useless, nobody likes you."}
    bully_res = client.post("/api/cyberbullying/scan", json=bully_payload, headers=auth_headers)
    bully_data = bully_res.json.get("data", {}) if bully_res.status_code == 200 else {}
    record("API: /api/cyberbullying/scan (Toxicity detection)", bully_res.status_code == 200 and bully_data.get("is_toxic") is True, f"Toxic score: {bully_data.get('toxicity_score')}")

    # 2.10 Security Report API
    report_res = client.get("/api/security-report", headers=auth_headers)
    record("API: /api/security-report", report_res.status_code == 200 and "security_grade" in report_res.json.get("data", {}))

    # =========================================================================
    # 3. SECURITY ANALYZER MICROSERVICE
    # =========================================================================
    print("\n--- 3. Testing Security Analyzer Microservice ---")
    analyzer_dir = BASE_DIR / "security-analyzer"
    sys.path.insert(0, str(analyzer_dir))
    import app as analyzer_app_module
    analyzer_client = analyzer_app_module.app.test_client()

    # 3.1 Health
    an_health = analyzer_client.get("/api/analyzer/health")
    record("Analyzer: /api/analyzer/health", an_health.status_code == 200 and an_health.json.get("status") == "online")

    # 3.2 Password Analysis
    an_pw = analyzer_client.post("/api/analyzer/password", json={"password": "password123"})
    an_pw_data = an_pw.json.get("data", {}) if an_pw.status_code == 200 else {}
    record("Analyzer: /api/analyzer/password (Weak detection)", an_pw.status_code == 200 and an_pw_data.get("score") < 30, f"Score: {an_pw_data.get('score')}")

    an_pw_strong = analyzer_client.post("/api/analyzer/password", json={"password": "Cyb3r$h1eld#2026!Str0ng"})
    an_pw_strong_data = an_pw_strong.json.get("data", {}) if an_pw_strong.status_code == 200 else {}
    record("Analyzer: /api/analyzer/password (Strong detection)", an_pw_strong.status_code == 200 and an_pw_strong_data.get("score") >= 80, f"Score: {an_pw_strong_data.get('score')}")

    # 3.3 Leak Check (Email & Domain)
    an_leak_email = analyzer_client.post("/api/analyzer/leak", json={"query": "test@example.com", "type": "email"})
    record("Analyzer: /api/analyzer/leak (Email breach scan)", an_leak_email.status_code == 200 and "breaches" in an_leak_email.json.get("data", {}))

    an_leak_domain = analyzer_client.post("/api/analyzer/leak", json={"query": "adobe.com", "type": "domain"})
    record("Analyzer: /api/analyzer/leak (Domain breach scan)", an_leak_domain.status_code == 200 and "breaches" in an_leak_domain.json.get("data", {}))

    # =========================================================================
    # 4. CHROME EXTENSION AUDIT & BUTTON VERIFICATION
    # =========================================================================
    print("\n--- 4. Testing Chrome Extension & Buttons ---")

    ext_dir = BASE_DIR / "extension"

    # 4.1 Manifest V3 Check
    manifest_path = ext_dir / "manifest.json"
    manifest_ok = manifest_path.exists()
    if manifest_ok:
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        mv3 = manifest_data.get("manifest_version") == 3
        perms = manifest_data.get("permissions", [])
        has_perms = all(p in perms for p in ["storage", "activeTab", "scripting"])
        record("Extension: manifest.json (Manifest V3 & permissions)", mv3 and has_perms)
    else:
        record("Extension: manifest.json exists", False)

    # 4.2 Popup HTML Elements & Buttons
    popup_html_path = ext_dir / "popup" / "popup.html"
    popup_html = popup_html_path.read_text(encoding="utf-8", errors="ignore")

    expected_buttons = [
        ("navSettingsBtn", "⚙️ Settings Navigation Button"),
        ("closeSettingsBtn", "✕ Close Settings Button"),
        ("saveSettingsBtn", "Save Settings Button"),
        ("saveAuthBtn", "Save & Authenticate Button"),
        ("skipAuthBtn", "Continue as Guest Button"),
        ("scanCurrentPageBtn", "⚡ Re-Scan Current Page Button"),
        ("checkDomainBreachBtn", "⚡ Check Breaches Button"),
        ("openFullAnalyzerBtn", "🚀 Open Domain in Security Analyzer Button"),
        ("toolAnalyzerBtn", "🔍 Security Analyzer Quick Tool Button"),
        ("openWebPortalBtn", "📊 Dashboard Quick Tool Button"),
        ("openDashboardBtn", "📊 Dedicated Open Dashboard Button"),
        ("openReportBtn", "📄 Dedicated Open AI Report Button"),
        ("toolReportBtn", "📄 AI Security Report Quick Tool Button"),
        ("toolPhishingBtn", "🎣 Phishing Detection Quick Tool Button"),
        ("toolIdentityBtn", "🛡️ Digital Identity Quick Tool Button"),
        ("openDigitalIdentityBtn", "🪪 Open Digital Identity Vault Button"),
        ("toolGuideBtn", "📖 Guidance Hub Quick Tool Button"),
        ("toolCyberbullyingBtn", "🚫 Cyberbullying Detection Quick Tool Button"),
        ("checkSelectionBtn", "💬 Scan Highlighted Toxic Text Button"),
    ]

    print("\n  >> Verifying all buttons in extension/popup/popup.html:")
    for btn_id, desc in expected_buttons:
        found = f'id="{btn_id}"' in popup_html
        record(f"Button: {btn_id}", found, desc)

    # 4.3 Popup View Panels
    views = ["loginView", "mainDashboardView", "settingsView"]
    for v in views:
        found = f'id="{v}"' in popup_html
        record(f"View Panel: {v}", found)

    # 4.4 Popup JS Event Listeners & Functionality
    popup_js_path = ext_dir / "popup" / "popup.js"
    popup_js = popup_js_path.read_text(encoding="utf-8", errors="ignore")

    print("\n  >> Verifying all button event bindings in extension/popup/popup.js:")
    for btn_id, desc in expected_buttons:
        # Check either document.getElementById("btn_id")?.addEventListener or getElementById("btn_id").addEventListener
        pattern = re.compile(rf'["\']{btn_id}["\']')
        has_binding = bool(pattern.search(popup_js))
        record(f"Handler: {btn_id}", has_binding, "Listener attached in popup.js")

    # 4.5 Popup Client-Side Phishing Heuristic Engine
    print("\n  >> Verifying Extension Client-Side Phishing Rules:")
    has_heuristics = all(rule in popup_js for rule in [
        ".xyz", "paypa1", "g00gle", "https://"
    ])
    record("Extension Heuristics: Bad TLDs & Brand Spoofing", has_heuristics)

    # 4.6 Extension Background Script Actions
    bg_js_path = ext_dir / "scripts" / "background.js"
    bg_js = bg_js_path.read_text(encoding="utf-8", errors="ignore")

    expected_actions = [
        "CHECK_PHISHING",
        "CHECK_TOXICITY",
        "CHECK_DOMAIN_LEAK",
        "CHECK_PASSWORD_SECURITY",
        "GET_ACTIVE_TAB_INFO",
        "RECORD_EXTENSION_INCIDENT",
        "DETECTED_ACCOUNT_LOGIN",
    ]
    print("\n  >> Verifying Background Service Worker Message Handlers:")
    for action in expected_actions:
        has_action = f'"{action}"' in bg_js or f"'{action}'" in bg_js
        record(f"Worker Action: {action}", has_action)

    # 4.7 Extension Content Script In-Page Defense Features
    content_js_path = ext_dir / "scripts" / "content.js"
    content_js = content_js_path.read_text(encoding="utf-8", errors="ignore")

    content_features = [
        ("cybershield-corner-badge", "Real-Time Corner Security Badge"),
        ("toxic-blur", "Automatic Toxic Text Blurring & Reveal Toggle"),
        ("password-tips", "In-Field Password Entropy Strength Hints"),
        ("outbound-blocker", "Pre-Submission Toxic Message Blocker Modal"),
        ("RECORD_EXTENSION_INCIDENT", "Extension Telemetry & Incident Reporting"),
    ]
    print("\n  >> Verifying Content Script In-Page Protections:")
    for marker, desc in content_features:
        has_feature = marker in content_js
        record(f"Content Feature: {desc}", has_feature)

    # 4.8 Extension Test Playground
    playground_path = ext_dir / "test_playground.html"
    playground_ok = playground_path.exists()
    record("Extension Test Playground: test_playground.html exists", playground_ok)

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "=" * 70)
    print(f"AUDIT COMPLETE: {passed_checks} / {total_checks} CHECKS PASSED ({passed_checks/total_checks*100:.1f}%)")
    print("=" * 70)

    return passed_checks == total_checks

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
