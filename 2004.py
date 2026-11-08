#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 eJPT LAB v1.0 - REAL-WORLD INTENTIONALLY VULNERABLE WEB APPLICATION
=====================================================================
 Entry point : app.py
 Port        : 2004
 Backend     : Flask + SQLite (raw SQL)
 Purpose     : eJPT / web pentest training (authorized lab only)

 WARNING: This application is DELIBERATELY INSECURE.
          Run it inside an isolated lab network / dedicated VPS only.
=====================================================================
"""

import os
import re
import json
import hmac
import time
import base64
import random
import string
import sqlite3
import hashlib
import datetime
import traceback

from flask import (Flask, request, Response, redirect, make_response, session,
                   jsonify, send_file, send_from_directory, abort)

# ---------------------------------------------------------------------
# PATHS / CONSTANTS
# ---------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "lab.db")
LAB_DIR    = os.path.join(BASE_DIR, "lab_files")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
LOG_DIR    = os.path.join(BASE_DIR, "logs")

SECRET_KEY      = "dev-secret-key-change-me"         # hardcoded
JWT_SECRET      = "s3cr3t_jwt_key_2024"              # hardcoded / weak
JWT_WEAK_SECRET = "secret"                           # alternate weak secret
MASTER_API_KEY  = "AKIA-EJPT-LAB-0001"               # hardcoded master key
ADMIN_USER      = "admin"
ADMIN_PASS      = "admin123"                         # hardcoded admin creds
DB_USER         = "labuser"
DB_PASS         = "labpass123"

DEBUG_MODE = os.environ.get("LAB_DEBUG", "0") == "1"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=False,     # VULN: no HttpOnly
    SESSION_COOKIE_SECURE=False,       # VULN: no Secure flag
    SESSION_COOKIE_SAMESITE=None,      # VULN: no SameSite
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    PROPAGATE_EXCEPTIONS=True,
)

random.seed(1337)

# ---------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------
def md5(v):
    return hashlib.md5(str(v).encode()).hexdigest()


def sha1(v):
    return hashlib.sha1(str(v).encode()).hexdigest()


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def log_event(message, level="INFO"):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO logs (ts, ip, method, path, level, message) VALUES (?,?,?,?,?,?)",
            (datetime.datetime.utcnow().isoformat(), request.remote_addr or "-",
             request.method, request.path, level, str(message)[:1000]),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def rnd_card():
    return "4" + "".join(random.choice(string.digits) for _ in range(15))


def b64u(raw):
    if isinstance(raw, str):
        raw = raw.encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64u(txt):
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


# ---------------------------------------------------------------------
# JWT (hand-rolled, intentionally broken)
# ---------------------------------------------------------------------
def jwt_encode(payload, secret=JWT_SECRET, alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    h = b64u(json.dumps(header, separators=(",", ":")))
    p = b64u(json.dumps(payload, separators=(",", ":")))
    if alg.lower() == "none":
        return f"{h}.{p}."
    sig = b64u(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def jwt_decode(token, secret=JWT_SECRET):
    """VULN: accepts alg=none and a weak fallback secret."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        header = json.loads(unb64u(parts[0]))
        payload = json.loads(unb64u(parts[1]))
        alg = str(header.get("alg", "HS256")).lower()

        if alg == "none":                       # <-- alg:none accepted
            return payload

        sig = parts[2] if len(parts) > 2 else ""
        for key in (secret, JWT_WEAK_SECRET):   # <-- weak secret accepted
            expected = b64u(hmac.new(key.encode(), f"{parts[0]}.{parts[1]}".encode(),
                                     hashlib.sha256).digest())
            if hmac.compare_digest(sig, expected):
                return payload
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------
# SEED DATA
# ---------------------------------------------------------------------
USER_SEED = [
    ("admin",     "admin123",   "admin@ejpt.lab",     "admin",     "Alisher Karimov"),
    ("root",      "toor",       "root@ejpt.lab",      "admin",     "Root Operator"),
    ("sysadmin",  "P@ssw0rd",   "sysadmin@ejpt.lab",  "admin",     "Dilshod Rahimov"),
    ("moderator", "mod123",     "moderator@ejpt.lab", "moderator", "Madina Yusupova"),
    ("mod_john",  "john2024",   "john@ejpt.lab",      "moderator", "John Smith"),
    ("mod_olga",  "qwerty123",  "olga@ejpt.lab",      "moderator", "Olga Petrova"),
    ("mod_aziz",  "aziz2024",   "aziz@ejpt.lab",      "moderator", "Aziz Toshpulatov"),
    ("alice",     "alice123",   "alice@ejpt.lab",     "user",      "Alice Johnson"),
    ("bob",       "bob2024",    "bob@ejpt.lab",       "user",      "Bob Brown"),
    ("charlie",   "charlie1",   "charlie@ejpt.lab",   "user",      "Charlie Davis"),
    ("diana",     "diana123",   "diana@ejpt.lab",     "user",      "Diana Prince"),
    ("emil",      "emil2024",   "emil@ejpt.lab",      "user",      "Emil Karimov"),
    ("farida",    "farida123",  "farida@ejpt.lab",    "user",      "Farida Nazarova"),
    ("guli",      "guli2024",   "guli@ejpt.lab",      "user",      "Gulnora Azizova"),
    ("hasan",     "hasan123",   "hasan@ejpt.lab",     "user",      "Hasan Tursunov"),
    ("ibrohim",   "ibrohim1",   "ibrohim@ejpt.lab",   "user",      "Ibrohim Sobirov"),
    ("jamila",    "jamila123",  "jamila@ejpt.lab",    "user",      "Jamila Ergasheva"),
    ("kamol",     "kamol2024",  "kamol@ejpt.lab",     "user",      "Kamol Ismoilov"),
    ("laylo",     "laylo123",   "laylo@ejpt.lab",     "user",      "Laylo Sharipova"),
    ("mansur",    "mansur1",    "mansur@ejpt.lab",    "user",      "Mansur Qodirov"),
    ("nargiza",   "nargiza1",   "nargiza@ejpt.lab",   "user",      "Nargiza Yuldasheva"),
    ("olim",      "olim2024",   "olim@ejpt.lab",      "user",      "Olim Rasulov"),
    ("parvina",   "parvina1",   "parvina@ejpt.lab",   "user",      "Parvina Saidova"),
    ("qodir",     "qodir123",   "qodir@ejpt.lab",     "user",      "Qodir Zokirov"),
    ("rustam",    "rustam1",    "rustam@ejpt.lab",    "user",      "Rustam Bekmurodov"),
    ("sabina",    "sabina12",   "sabina@ejpt.lab",    "user",      "Sabina Umarova"),
    ("temur",     "temur123",   "temur@ejpt.lab",     "user",      "Temur Aliyev"),
    ("umid",      "umid2024",   "umid@ejpt.lab",      "user",      "Umid Xolmatov"),
    ("vali",      "vali1234",   "vali@ejpt.lab",      "user",      "Vali Ergashev"),
    ("zulfiya",   "zulfiya1",   "zulfiya@ejpt.lab",   "user",      "Zulfiya Nazarova"),
    ("nodira",    "nodira12",   "nodira@ejpt.lab",    "user",      "Nodira Karimova"),
    ("testuser",  "test123",    "test@ejpt.lab",      "user",      "Test User"),
]

FLAGS = [
    ("EJPT{sqli_union_01}",         "SQLi UNION-based",            "SQL Injection",  "Easy",   50),
    ("EJPT{sqli_boolean_02}",       "SQLi Boolean-based",          "SQL Injection",  "Medium", 75),
    ("EJPT{sqli_error_03}",         "SQLi Error-based",            "SQL Injection",  "Easy",   50),
    ("EJPT{auth_bypass_04}",        "Login Auth Bypass",           "Auth",           "Easy",   50),
    ("EJPT{idor_profile_05}",       "IDOR Profile Read",           "Access Control", "Easy",   50),
    ("EJPT{idor_document_06}",      "IDOR Document Read",          "Access Control", "Medium", 75),
    ("EJPT{idor_invoice_07}",       "IDOR Predictable Invoice",    "Access Control", "Easy",   50),
    ("EJPT{reflected_xss_08}",      "Reflected XSS",               "XSS",            "Easy",   50),
    ("EJPT{stored_xss_09}",         "Stored XSS",                  "XSS",            "Medium", 75),
    ("EJPT{dom_xss_10}",            "DOM-based XSS",               "XSS",            "Medium", 75),
    ("EJPT{path_traversal_11}",     "Path Traversal",              "File",           "Medium", 75),
    ("EJPT{lfi_12}",                "Local File Inclusion",        "File",           "Medium", 75),
    ("EJPT{csrf_email_13}",         "CSRF Email Change",           "CSRF",           "Easy",   50),
    ("EJPT{csrf_transfer_14}",      "CSRF Money Transfer",         "CSRF",           "Medium", 75),
    ("EJPT{open_redirect_15}",      "Open Redirect",               "Web",            "Easy",   50),
    ("EJPT{bac_admin_16}",          "Broken Access Control /admin","Access Control", "Easy",   50),
    ("EJPT{weak_session_17}",       "Weak Session Management",     "Session",        "Medium", 75),
    ("EJPT{cookie_admin_18}",       "Cookie Manipulation -> Admin","Session",        "Medium", 75),
    ("EJPT{info_disclosure_19}",    "Info Disclosure /server-info","Info Leak",      "Easy",   50),
    ("EJPT{dir_listing_20}",        "Directory Listing",           "Info Leak",      "Easy",   50),
    ("EJPT{backup_exposure_21}",    "Backup File Exposure",        "Info Leak",      "Medium", 75),
    ("EJPT{upload_bypass_22}",      "Unrestricted File Upload",    "File",           "Medium", 75),
    ("EJPT{weak_md5_23}",           "MD5 Unsalted Hashing",        "Crypto",         "Easy",   50),
    ("EJPT{hash_exposure_24}",      "Hash Exposure via API",       "Info Leak",      "Easy",   50),
    ("EJPT{hardcoded_creds_25}",    "Hardcoded Credentials",       "Info Leak",      "Easy",   50),
    ("EJPT{jwt_alg_none_26}",       "JWT alg=none",                "JWT",            "Hard",   100),
    ("EJPT{jwt_weak_secret_27}",    "JWT Weak Secret",             "JWT",            "Hard",   100),
    ("EJPT{api_key_leak_28}",       "API Key in URL",              "API",            "Easy",   50),
    ("EJPT{excessive_data_29}",     "Excessive Data Exposure",     "API",            "Easy",   50),
    ("EJPT{verbose_error_30}",      "Verbose Error Messages",      "Config",         "Easy",   50),
    ("EJPT{misconfig_31}",          "Security Misconfiguration",   "Config",         "Medium", 75),
    ("EJPT{cors_32}",               "CORS Misconfiguration",       "Config",         "Medium", 75),
    ("EJPT{http_method_33}",        "HTTP Method Misconfig",       "Config",         "Easy",   50),
    ("EJPT{no_headers_34}",         "Missing Security Headers",    "Config",         "Easy",   50),
    ("EJPT{pwd_reset_35}",          "Weak Password Reset",         "Auth",           "Hard",   100),
    ("EJPT{mass_assign_36}",        "Mass Assignment",             "API",            "Hard",   100),
    ("EJPT{rate_limit_37}",         "No Rate Limiting OTP",        "Auth",           "Medium", 75),
    ("EJPT{hidden_admin_38}",       "Hidden Admin Panel",          "Access Control", "Medium", 75),
    ("EJPT{db_design_39}",          "Insecure DB Design",          "DB",             "Easy",   50),
    ("EJPT{user_enum_40}",          "User Enumeration",            "Auth",           "Easy",   50),
    ("EJPT{predictable_ids_41}",    "Predictable Resource IDs",    "Access Control", "Easy",   50),
    ("EJPT{graphql_42}",            "GraphQL Introspection",       "API",            "Medium", 75),
    ("EJPT{server_banner_43}",      "Server Banner Disclosure",    "Info Leak",      "Easy",   50),
    ("EJPT{broken_auth_44}",        "Broken Auth / No Expiry",     "Auth",           "Medium", 75),
    ("EJPT{session_forge_45}",      "Session Forgery",             "Session",        "Hard",   100),
    ("EJPT{log_injection_46}",      "Log Injection",               "Web",            "Medium", 75),
    ("EJPT{api_ssrf_47}",           "API Improper Input Handling", "API",            "Medium", 75),
    ("EJPT{admin_note_48}",         "Admin Secret Note",           "Access Control", "Medium", 75),
    ("EJPT{config_file_48}",        "Config File Leak",            "Info Leak",      "Easy",   50),
    ("EJPT{db_dump_49}",            "Database Dump",               "Info Leak",      "Medium", 75),
    ("EJPT{card_data_50}",          "Plaintext Card Data",         "DB",             "Easy",   50),
    ("EJPT{jwt_user_forge_51}",     "JWT Privilege Escalation",    "JWT",            "Hard",   100),
    ("EJPT{idor_notes_52}",         "IDOR Private Notes",          "Access Control", "Medium", 75),
    ("EJPT{xss_cookie_steal_53}",   "XSS + Cookie Theft",          "XSS",            "Hard",   100),
    ("EJPT{full_chain_54}",         "Full Chain to Admin",         "Chain",          "Hard",   150),
    ("EJPT{master_55}",             "Master Flag (admin panel)",   "Chain",          "Hard",   200),
]

CHALLENGES = [
    ("SQL Injection (UNION-based)", "GET /product?id=1", "GET", "Easy",
     "Mahsulot ID parametri to'g'ridan-to'g'ri SQL so'rovga qo'shiladi.",
     "UNION SELECT orqali users jadvalidan hash olish."),
    ("SQL Injection (Boolean-based)", "GET /product?id=1", "GET", "Medium",
     "AND 1=1 / AND 1=2 javoblari farq qiladi.",
     "True/False javob orqali ma'lumot chiqarish."),
    ("SQL Injection (Error-based)", "GET /product?id=1'", "GET", "Easy",
     "Xato matni baza strukturasi va so'rovni ko'rsatadi.",
     "SQLite xato xabari sahifada ko'rinadi."),
    ("Authentication Bypass", "POST /login", "POST", "Easy",
     "Login SQL so'rovi string konkatensatsiya bilan quriladi.",
     "admin' -- bilan parolsiz kirish."),
    ("IDOR (Profile)", "GET /api/user/1", "GET", "Easy",
     "Foydalanuvchi ID to'g'ridan-to'g'ri obyektga bog'langan, avtorizatsiya yo'q.",
     "Boshqa foydalanuvchi ma'lumotlari (hash, card) ko'rinadi."),
    ("IDOR (Document)", "GET /documents/1", "GET", "Medium",
     "Hujjat egasi tekshirilmaydi.",
     "Maxfiy hujjat mazmuni va flag olinadi."),
    ("IDOR (Predictable IDs)", "GET /invoice/1", "GET", "Easy",
     "Invoys ID ketma-ket.",
     "/invoice/1..20 barcha to'lovlar ko'rinadi."),
    ("Reflected XSS", "GET /search?q=<script>alert(1)</script>", "GET", "Easy",
     "q parametri HTML escape qilinmasdan chiqariladi.",
     "Brauzerda JS bajariladi."),
    ("Stored XSS", "POST /blog/comment", "POST", "Medium",
     "Izohlar bazaga saqlanadi va xom holda render qilinadi.",
     "Har bir tashrif buyuruvchida JS ishlaydi."),
    ("DOM-based XSS", "GET /domxss#<img src=x onerror=alert(1)>", "GET", "Medium",
     "location.hash innerHTML ga yoziladi.",
     "Client-side JS bajariladi."),
    ("Path Traversal", "GET /download?file=../app.py", "GET", "Medium",
     "Fayl nomi normalize qilinmaydi.",
     "Ish katalogidagi fayllar o'qiladi."),
    ("Local File Inclusion", "GET /page?name=about", "GET", "Medium",
     "Sahifa nomi fayl sifatida include qilinadi.",
     "?name=../lab_files/secret.txt mazmuni chiqadi."),
    ("CSRF (Email)", "POST /settings/email", "POST", "Easy",
     "Tokenni tekshirish yo'q.",
     "CSRF PoC bilan email o'zgartiriladi."),
    ("CSRF (Transfer)", "POST /transfer", "POST", "Medium",
     "Pul o'tkazmasi CSRF tokenisiz.",
     "Balans boshqa hisobga o'tadi."),
    ("Open Redirect", "GET /redirect?url=https://evil.com", "GET", "Easy",
     "url parametri tekshirilmaydi.",
     "302 Location: attacker sayt."),
    ("Broken Access Control", "GET /admin", "GET", "Easy",
     "Admin panel uchun hech qanday tekshiruv yo'q.",
     "Barcha userlar, hash, flag ko'rinadi."),
    ("Broken Access Control (API)", "GET /api/admin/users", "GET", "Easy",
     "Admin API avtorizatsiyasiz.",
     "To'liq userlar ro'yxati JSON."),
    ("Weak Session Management", "POST /api/login", "POST", "Medium",
     "Cookie'da uid va role ochiq matnda, HttpOnly yo'q.",
     "Cookie'ni qo'lda o'zgartirish mumkin."),
    ("Cookie Manipulation", "GET /dashboard", "GET", "Medium",
     "Dashboard role cookie'siga ishonadi.",
     "role=admin qilib admin panelga o'tiladi."),
    ("Information Disclosure", "GET /server-info", "GET", "Easy",
     "Server konfiguratsiyasi, yo'llar, versiyalar oshkor.",
     "Env va path ma'lumotlari."),
    ("Directory Listing", "GET /files/", "GET", "Easy",
     "Katalog ichidagi fayllar ro'yxati chiqadi.",
     "Yashirin fayllar topiladi."),
    ("Backup File Exposure", "GET /backups/", "GET", "Medium",
     "app.py.bak va db.sql ochiq.",
     "Manba kod va DB dump yuklab olinadi."),
    ("Insecure File Upload", "POST /upload", "POST", "Medium",
     "Fayl turi va nomi tekshirilmaydi.",
     ".html/.php yuklanadi va /uploads/ dan ochiladi."),
    ("Weak Password Hashing", "GET /api/user/1", "GET", "Easy",
     "MD5 salt'siz ishlatiladi.",
     "Hash crack (hashcat/john) bilan parol topiladi."),
    ("Hash Exposure", "GET /api/v1/users", "GET", "Easy",
     "API barcha hash'larni qaytaradi.",
     "MD5 + SHA1 birga olinadi."),
    ("Hardcoded Credentials", "GET /api/config", "GET", "Easy",
     "JWT secret, DB parol, admin parol kodda.",
     "Konfiguratsiya JSON sifatida olinadi."),
    ("JWT alg=none", "POST /api/jwt/me", "POST", "Hard",
     "Imzo tekshirilmaydi agar alg=none bo'lsa.",
     "Token forge qilib admin bo'linadi."),
    ("JWT Weak Secret", "POST /api/jwt/me", "POST", "Hard",
     "Secret 'secret' ham qabul qilinadi.",
     "hashcat -m 16500 bilan secret topiladi."),
    ("API Auth Weakness", "GET /api/v1/users?api_key=AKIA-EJPT-LAB-0001", "GET", "Easy",
     "Master API key URL'da va hamma joyda ishlaydi.",
     "Key'siz ham ?api_key= bilan kirish."),
    ("Excessive Data Exposure", "GET /api/v1/users", "GET", "Easy",
     "API ortiqcha maydonlarni qaytaradi (ssn, card).",
     "Moliyaviy ma'lumotlar oshkor."),
    ("Verbose Error Messages", "GET /product?id=x", "GET", "Easy",
     "Traceback foydalanuvchiga ko'rsatiladi.",
     "Stack trace va fayl yo'llari."),
    ("Security Misconfiguration", "GET /debug", "GET", "Medium",
     "Debug sahifa env va configni ko'rsatadi.",
     "Ichki sozlamalar oshkor."),
    ("CORS Misconfiguration", "OPTIONS /api/v1/users", "OPTIONS", "Medium",
     "ACAO: * + Allow-Credentials: true.",
     "Cross-origin credential bilan o'qish."),
    ("HTTP Method Misconfiguration", "GET /api/v1/delete_user?id=8", "GET", "Easy",
     "O'chirish GET bilan ishlaydi.",
     "GET so'rov bilan user o'chiriladi."),
    ("Missing Security Headers", "GET /", "GET", "Easy",
     "CSP, HSTS, X-Frame-Options yo'q.",
     "Nikto/curl -I bilan tasdiqlanadi."),
    ("Weak Password Reset", "GET /reset-password?email=alice@ejpt.lab&token=<md5(email)>&password=NewPass1", "GET", "Hard",
     "Token = md5(email), muddati yo'q.",
     "Har qanday user parolini almashtirish."),
    ("Mass Assignment", "POST /api/profile/update", "POST", "Hard",
     "JSON barcha maydonlarni yangilaydi, role ham.",
     "{\"uid\":8,\"role\":\"admin\"} -> admin."),
    ("Rate Limiting Weakness", "GET /api/otp/verify?user=admin&code=1234", "GET", "Medium",
     "Cheksiz urinish, OTP qisqa va predictab.",
     "Brute force bilan OTP topiladi."),
    ("Hidden Admin Panel", "GET /administrator.php", "GET", "Medium",
     "Yashirin panel avtorizatsiyasiz.",
     "Faqat endpoint nomini topish kerak."),
    ("Sensitive Information Exposure", "GET /api/debug/env", "GET", "Easy",
     "Environment o'zgaruvchilari ochiq.",
     "SECRET_KEY, JWT secret."),
    ("Insecure Database Design", "GET /api/v1/orders", "GET", "Easy",
     "Karta raqamlari plaintext.",
     "PCI-DSS buzilishi, karta ma'lumotlari."),
    ("Broken Authentication", "GET /api/v1/me?token=...", "GET", "Medium",
     "Token muddati yo'q, bekor qilinmaydi.",
     "Eski token abadiy ishlaydi."),
    ("User Enumeration", "GET /api/check-user?username=admin", "GET", "Easy",
     "Mavjud/mavjud emas javobi farq qiladi.",
     "Username ro'yxati tuziladi."),
    ("GraphQL Introspection", "POST /graphql", "POST", "Medium",
     "Introspection yoqilgan, auth yo'q.",
     "{__schema{types{name}}} bilan sxema olinadi."),
    ("Server Info Disclosure", "GET /", "GET", "Easy",
     "Server/X-Powered-By header'lari.",
     "Werkzeug versiyasi aniqlanadi."),
]

# ---------------------------------------------------------------------
# UI LAYOUT
# ---------------------------------------------------------------------
CSS = """
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,Arial,sans-serif;background:#0f1720;color:#d7e1ec}
a{color:#4fc3f7;text-decoration:none}
a:hover{text-decoration:underline}
.nav{background:#152230;padding:12px 20px;border-bottom:2px solid #1f3b52;display:flex;flex-wrap:wrap;gap:14px;align-items:center}
.nav b{color:#ffb74d;margin-right:10px}
main{max-width:1100px;margin:24px auto;padding:0 18px}
h1,h2{color:#81d4fa}
table{width:100%;border-collapse:collapse;margin:14px 0;font-size:14px}
th,td{border:1px solid #24425c;padding:8px;text-align:left;vertical-align:top}
th{background:#173047;color:#b3e5fc}
tr:nth-child(even){background:#131f2b}
input,textarea,select{background:#0b141c;border:1px solid #2c4b66;color:#e6f1fa;padding:8px;border-radius:4px;width:100%;margin:4px 0}
button{background:#1e88e5;color:#fff;border:0;padding:10px 18px;border-radius:4px;cursor:pointer}
button:hover{background:#1565c0}
pre{background:#0b141c;border:1px solid #24425c;padding:12px;overflow:auto;font-size:13px;color:#a5d6a7}
.card{background:#152230;border:1px solid #24425c;border-radius:6px;padding:16px;margin:14px 0}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;background:#1e88e5;color:#fff}
.easy{background:#2e7d32}.medium{background:#ef6c00}.hard{background:#c62828}
footer{text-align:center;color:#546e7a;font-size:12px;padding:30px}
.flag{color:#ffd54f;font-family:monospace}
"""

LAYOUT = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>{{TITLE}} | eJPT LAB</title><style>' + CSS + '</style></head><body>'
    '<div class="nav"><b>eJPT LAB</b>'
    '<a href="/">Home</a><a href="/product?id=1">Products</a>'
    '<a href="/search">Search</a><a href="/blog">Blog</a>'
    '<a href="/upload">Upload</a><a href="/files/">Files</a>'
    '<a href="/login">Login</a><a href="/dashboard">Dashboard</a>'
    '<a href="/admin">Admin</a><a href="/challenges">Challenges</a>'
    '<a href="/server-info">Server</a><a href="/graphql">GraphQL</a>'
    '</div><main>{{BODY}}</main>'
    '<footer>eJPT LAB v1.0 - intentionally vulnerable training application</footer>'
    '</body></html>'
)


def page(title, body):
    return LAYOUT.replace("{{TITLE}}", title).replace("{{BODY}}", body)


# ---------------------------------------------------------------------
# DATABASE INIT / SEED
# ---------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY, username TEXT, password_md5 TEXT, password_sha1 TEXT,
    email TEXT, role TEXT, full_name TEXT, api_key TEXT, ssn TEXT,
    credit_card TEXT, balance REAL, is_active INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS products(
    id INTEGER PRIMARY KEY, name TEXT, price REAL, description TEXT);
CREATE TABLE IF NOT EXISTS notes(
    id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, content TEXT, is_private INTEGER);
CREATE TABLE IF NOT EXISTS orders(
    id INTEGER PRIMARY KEY, user_id INTEGER, product TEXT, amount REAL,
    status TEXT, card_number TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS invoices(
    id INTEGER PRIMARY KEY, user_id INTEGER, reference TEXT, amount REAL, paid INTEGER);
CREATE TABLE IF NOT EXISTS documents(
    id INTEGER PRIMARY KEY, user_id INTEGER, filename TEXT, content TEXT, classification TEXT);
CREATE TABLE IF NOT EXISTS comments(
    id INTEGER PRIMARY KEY, user_id INTEGER, author TEXT, content TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS flags(
    id INTEGER PRIMARY KEY, code TEXT, name TEXT, category TEXT, difficulty TEXT NOT NULL, points INTEGER);
CREATE TABLE IF NOT EXISTS challenges(
    id INTEGER PRIMARY KEY, name TEXT, endpoint TEXT, method TEXT, difficulty TEXT,
    description TEXT, expected TEXT);
CREATE TABLE IF NOT EXISTS logs(
    id INTEGER PRIMARY KEY, ts TEXT, ip TEXT, method TEXT, path TEXT, level TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS sessions(
    id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS reset_tokens(
    email TEXT PRIMARY KEY, token TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS otp(
    username TEXT PRIMARY KEY, code TEXT);
CREATE TABLE IF NOT EXISTS api_tokens(
    id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT, created_at TEXT);
"""


def init_db():
    for d in (LAB_DIR, UPLOAD_DIR, BACKUP_DIR, LOG_DIR):
        os.makedirs(d, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript(SCHEMA)

    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        print("[*] Seeding database ...")

        for i, (u, p, email, role, name) in enumerate(USER_SEED, start=1):
            c.execute(
                "INSERT INTO users (id,username,password_md5,password_sha1,email,role,"
                "full_name,api_key,ssn,credit_card,balance,is_active,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (i, u, md5(p), sha1(p), email, role, name,
                 f"AKIA-LAB-{1000 + i}",
                 f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}",
                 rnd_card(), round(random.uniform(100, 5000), 2), 1,
                 datetime.datetime.utcnow().isoformat()),
            )

        products = [
            (1, "Wireless Keyboard", 49.99, "Ergonomic 2.4GHz wireless keyboard."),
            (2, "USB-C Hub", 34.50, "7-in-1 USB-C multiport adapter."),
            (3, "Gaming Mouse", 59.00, "16000 DPI optical gaming mouse."),
            (4, "27\" Monitor", 219.99, "IPS 75Hz full HD monitor."),
            (5, "Laptop Stand", 25.00, "Aluminium adjustable stand."),
            (6, "Noise Cancelling Headphones", 129.90, "ANC over-ear headphones."),
            (7, "External SSD 1TB", 99.95, "USB 3.2 portable SSD."),
            (8, "Webcam 1080p", 45.00, "Full HD webcam with microphone."),
        ]
        c.executemany("INSERT INTO products VALUES (?,?,?,?)", products)

        notes = [
            (1, 1, "Root credentials", "EJPT{admin_note_48} - root/toor superuser account for lab.", 1),
            (2, 1, "DB backup location", "Backups live in /backups/db.sql (do not expose!).", 1),
            (3, 4, "Moderation queue", "Reported spam users: bob, charlie.", 0),
            (4, 8, "Personal note", "EJPT{idor_notes_52} - my private flag.", 1),
            (5, 9, "Bank details", "IBAN UZ11 0000 1111 2222 3333 4444", 1),
            (6, 12, "API notes", "Master key: AKIA-EJPT-LAB-0001", 1),
            (7, 2, "JWT config", "JWT secret: s3cr3t_jwt_key_2024", 1),
            (8, 15, "Reminder", "Change default admin password!", 0),
            (9, 20, "Secret project", "EJPT{full_chain_54} - chain reaches admin.", 1),
            (10, 25, "Pickup code", "Locker 4412, code 9981.", 1),
        ]
        c.executemany("INSERT INTO notes VALUES (?,?,?,?,?)", notes)

        for i in range(1, 16):
            uid = random.randint(1, len(USER_SEED))
            c.execute(
                "INSERT INTO orders (user_id,product,amount,status,card_number,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (uid, random.choice(products)[1], round(random.uniform(20, 400), 2),
                 random.choice(["paid", "pending", "refunded"]), rnd_card(),
                 datetime.datetime.utcnow().isoformat()),
            )

        for i in range(1, 13):
            c.execute("INSERT INTO invoices VALUES (?,?,?,?,?)",
                      (i, random.randint(1, len(USER_SEED)), f"INV-2024-{1000 + i}",
                       round(random.uniform(50, 900), 2), random.choice([0, 1])))

        docs = [
            (1, 8, "passport_scan.txt", "EJPT{idor_document_06} - PASSPORT: AA1234567", "PRIVATE"),
            (2, 9, "salary_2024.txt", "Salary review notes, confidential.", "PRIVATE"),
            (3, 1, "admin_manual.txt", "Admin manual: /administrator.php is the real panel.", "INTERNAL"),
            (4, 12, "api_keys.txt", "AKIA-LAB-1012 / AKIA-LAB-1001", "SECRET"),
            (5, 15, "network_map.txt", "10.10.10.0/24 lab range, 2004 web.", "INTERNAL"),
            (6, 20, "flag_note.txt", "EJPT{path_traversal_11} - traversal works.", "SECRET"),
            (7, 22, "backup_hint.txt", "/backups/app.py.bak contains source.", "INTERNAL"),
            (8, 25, "token.txt", "EJPT{broken_auth_44} - token never expires.", "SECRET"),
        ]
        c.executemany("INSERT INTO documents VALUES (?,?,?,?,?)", docs)

        c.execute("INSERT INTO comments (user_id,author,content,created_at) VALUES (?,?,?,?)",
                  (8, "alice", "Great shop, fast delivery!", datetime.datetime.utcnow().isoformat()))
        c.execute("INSERT INTO comments (user_id,author,content,created_at) VALUES (?,?,?,?)",
                  (9, "bob", "Nice products.", datetime.datetime.utcnow().isoformat()))

        for f in FLAGS:
            c.execute("INSERT INTO flags (code,name,category,difficulty,points) VALUES (?,?,?,?,?)", f)

        for ch in CHALLENGES:
            c.execute("INSERT INTO challenges (name,endpoint,method,difficulty,description,expected) "
                      "VALUES (?,?,?,?,?,?)", ch)

        c.execute("INSERT INTO otp VALUES (?,?)", ("admin", "4821"))
        c.execute("INSERT INTO otp VALUES (?,?)", ("alice", "7392"))

        conn.commit()

    conn.close()

    # ---- lab files ----
    lab_files = {
        "readme.txt": "eJPT LAB files directory.\nTry: /download?file=../app.py\n",
        "about.html": "<h3>About eJPT LAB</h3><p>Training target application.</p>",
        "credentials.txt": "\n".join(f"{u}:{p}" for u, p, *_ in USER_SEED[:20]) + "\n",
        "secret.txt": "EJPT{config_file_48} - secret lab file.\nAdmin panel: /administrator.php\n",
        "config.ini": "[database]\nuser=labuser\npassword=labpass123\njwt_secret=s3cr3t_jwt_key_2024\n",
        "notes.txt": "TODO: remove backups, disable debug, rotate API keys.\n",
        "network.txt": "10.10.10.0/24\nweb: 2004\n",
    }
    for name, content in lab_files.items():
        p = os.path.join(LAB_DIR, name)
        if not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)

    # ---- backups ----
    bak = os.path.join(BACKUP_DIR, "app.py.bak")
    try:
        with open(os.path.abspath(__file__), "r", encoding="utf-8") as src, \
                open(bak, "w", encoding="utf-8") as dst:
            fh_content = src.read()
            fh.write(dump_placeholder := "") if False else None
            dst.write(fh_content)
    except Exception:
        pass

    dump_path = os.path.join(BACKUP_DIR, "db.sql")
    if not os.path.exists(dump_path):
        try:
            conn = sqlite3.connect(DB_PATH)
            with open(dump_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(conn.iterdump()))
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------
# GLOBAL HOOKS
# ---------------------------------------------------------------------
@app.before_request
def _log():
    if request.path.startswith("/static"):
        return
    log_event(f"{request.method} {request.full_path}")


@app.after_request
def _headers(resp):
    # VULN: permissive CORS with credentials
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    # VULN: version disclosure
    resp.headers["X-Powered-By"] = "Flask/2.3.3"
    resp.headers["Server"] = "Werkzeug/2.3.7 Python/3.11"
    return resp


@app.errorhandler(Exception)
def _err(e):
    # VULN: verbose error / full traceback
    tb = traceback.format_exc()
    code = getattr(e, "code", 500) or 500
    body = (
        "<h1>Internal Server Error</h1>"
        f"<p><b>{type(e).__name__}:</b> {e}</p>"
        "<h3>Traceback</h3><pre>" + tb + "</pre>"
        f"<h3>Request</h3><pre>{request.method} {request.full_path}\n"
        f"DB: {DB_PATH}\nCWD: {os.getcwd()}</pre>"
    )
    return page("Error", body), code


# ---------------------------------------------------------------------
# PUBLIC PAGES
# ---------------------------------------------------------------------
@app.route("/")
def index():
    return page("Home", """
    <h1>eJPT Lab Store</h1>
    <div class="card">
      <p>Welcome to the intentionally vulnerable training store.
      Browse products, read the blog, upload files and poke around.</p>
      <p><b>Quick links:</b> <a href="/product?id=1">Products</a> |
      <a href="/login">Login</a> | <a href="/challenges">Challenge list</a></p>
    </div>
    <div class="card">
      <h3>Test accounts</h3>
      <pre>admin / admin123
alice / alice123
bob   / bob2024
testuser / test123</pre>
    </div>
    """)


@app.route("/robots.txt")
def robots():
    txt = ("User-agent: *\nDisallow: /admin\nDisallow: /administrator.php\n"
           "Disallow: /backups/\nDisallow: /api/\nDisallow: /debug\n"
           "Disallow: /files/\nDisallow: /server-info\n")
    return Response(txt, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    urls = ["/", "/product?id=1", "/blog", "/upload", "/files/", "/login",
            "/admin", "/administrator.php", "/api/v1/users", "/graphql", "/server-info"]
    items = "".join(f"<url><loc>http://{request.host}{u}</loc></url>" for u in urls)
    return Response(
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{items}</urlset>',
        mimetype="application/xml")


# ---------------------------- SQL INJECTION --------------------------
@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    conn = get_db()
    query = f"SELECT id, name, price, description FROM products WHERE id = {pid}"  # VULN
    rows = []
    err = None
    try:
        rows = conn.execute(query).fetchall()
    except Exception as e:
        err = str(e)
    conn.close()

    out = [f"<h1>Product details</h1><p>Query: <code>{query}</code></p>"]
    if err:
        out.append(f"<div class='card'><b>SQL error:</b><pre>{err}</pre></div>")
    if not rows and not err:
        out.append("<p>No product found.</p>")
    for r in rows:
        out.append(
            "<div class='card'><h3>" + str(r["name"]) + "</h3>"
            f"<p>ID: {r['id']} | Price: {r['price']}</p>"
            f"<p>{r['description']}</p></div>"
        )
    out.append("<p><a href='/product?id=1'>&laquo; back</a></p>")
    return page("Product", "".join(out))


# ---------------------------- AUTH -----------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page("Login", """
        <h1>Login</h1>
        <div class="card">
        <form method="post" action="/login">
          <label>Username</label><input name="username" value="">
          <label>Password</label><input name="password" type="password">
          <button type="submit">Sign in</button>
        </form>
        <p><a href="/forgot-password">Forgot password?</a></p>
        </div>""")

    u = request.form.get("username", "")
    p = request.form.get("password", "")
    conn = get_db()
    query = f"SELECT * FROM users WHERE username = '{u}' AND password_md5 = '{md5(p)}'"  # VULN
    try:
        row = conn.execute(query).fetchone()
    except Exception as e:
        conn.close()
        return page("Login error", f"<h1>SQL error</h1><pre>{e}</pre><p>Query: {query}</p>"), 500
    conn.close()

    if not row:
        return page("Login", "<h1>Login failed</h1><p>Invalid credentials.</p>"
                             "<p><a href='/login'>Try again</a></p>"), 401

    token = b64u(f"{row['id']}:{row['username']}:{int(time.time())}")
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("auth", f"{row['id']}:{row['role']}", httponly=False)   # VULN
    resp.set_cookie("uid", str(row["id"]), httponly=False)                  # VULN
    resp.set_cookie("role", row["role"], httponly=False)                    # VULN
    resp.set_cookie("token", token, httponly=False)                         # VULN
    session["uid"] = row["id"]
    session["role"] = row["role"]
    conn = get_db()
    conn.execute("INSERT INTO sessions (user_id,token,created_at) VALUES (?,?,?)",
                 (row["id"], token, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return resp


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect("/"))
    for c in ("auth", "uid", "role", "token"):
        resp.delete_cookie(c)
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return page("Register", """
        <h1>Register</h1><div class="card">
        <form method="post" action="/register">
          <label>Username</label><input name="username">
          <label>Email</label><input name="email">
          <label>Password</label><input name="password" type="password">
          <label>Role (internal)</label><input name="role" value="user">
          <button type="submit">Create account</button>
        </form></div>""")

    u = request.form.get("username", "")
    email = request.form.get("email", "")
    p = request.form.get("password", "")
    role = request.form.get("role", "user")     # VULN: mass assignment / role injection
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username,password_md5,password_sha1,email,role,full_name,"
            "api_key,ssn,credit_card,balance,is_active,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (u, md5(p), sha1(p), email, role, u, f"AKIA-LAB-{random.randint(2000, 9999)}",
             "000-00-0000", rnd_card(), 0.0, 1, datetime.datetime.utcnow().isoformat()),
        )
        conn.commit()
        new_id = conn.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone()[0]
    except Exception as e:
        conn.close()
        return page("Register", f"<h1>Registration error</h1><pre>{e}</pre>"), 500
    conn.close()
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("uid", str(new_id), httponly=False)
    resp.set_cookie("role", role, httponly=False)
    resp.set_cookie("auth", f"{new_id}:{role}", httponly=False)
    return resp


@app.route("/dashboard")
def dashboard():
    # VULN: trusts client-side cookies completely
    uid = request.cookies.get("uid", "")
    role = request.cookies.get("role", "guest")
    if not uid:
        return redirect("/login")
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    if not row:
        return page("Dashboard", "<h1>Unknown user</h1><p>Cookie forge qilingan?</p>"), 404

    body = [
        f"<h1>Dashboard</h1><p>Logged in as <b>{row['username']}</b> "
        f"(role cookie: <span class='badge'>{role}</span>)</p>",
        f"<div class='card'><p>Email: {row['email']}</p><p>Balance: {row['balance']}</p>"
        f"<p>API key: <code>{row['api_key']}</code></p></div>",
    ]
    if role == "admin":
        body.append("<div class='card'><h3>Admin area</h2>"
                    "<p>EJPT{cookie_admin_18} - cookie manipulation works.</p>"
                    "<p><a href='/admin'>Open admin panel</a></p></div>")
    body.append("<p><a href='/logout'>Logout</a></p>")
    return page("Dashboard", "".join(body))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot():
    if request.method == "GET":
        return page("Forgot password", """
        <h1>Forgot password</h1><div class="card">
        <form method="post" action="/forgot-password">
          <label>Email</label><input name="email">
          <button type="submit">Send reset link</button>
        </form></div>""")

    email = request.form.get("email", "")
    token = md5(email)          # VULN: predictable token
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO reset_tokens (email,token,created_at) VALUES (?,?,?)",
                 (email, token, datetime.datetime.utcnow().isoformat()))   # VULN: no expiry
    conn.commit()
    conn.close()
    link = f"/reset-password?email={email}&token={token}&password=NewPass123"
    return page("Reset link", f"<h1>Reset link generated</h1>"
                              f"<div class='card'><a href='{link}'>{link}</a></div>")


@app.route("/reset-password")
def reset_password():
    email = request.args.get("email", "")
    token = request.args.get("token", "")
    newpass = request.args.get("password", "")
    conn = get_db()
    row = conn.execute("SELECT * FROM reset_tokens WHERE email=?", (email,)).fetchone()
    if not row or row["token"] != token:
        conn.close()
        return page("Reset", "<h1>Invalid token</h1>"), 403
    conn.execute("UPDATE users SET password_md5=?, password_sha1=? WHERE email=?",
                 (md5(newpass), sha1(newpass), email))
    conn.commit()
    conn.close()
    return page("Reset", f"<h1>Password changed</h1><p>New password: {newpass}</p>"
                         "<p>EJPT{pwd_reset_35}</p>")


# ---------------------------- XSS ------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: reflected XSS - no escaping
    body = f"""
    <h1>Search</h1>
    <form method="get" action="/search">
      <input name="q" value="{q}" placeholder="Search products...">
      <button type="submit">Search</button>
    </form>
    <div class="card">Siz qidirdingiz: {q}</div>
    """ if q else """
    <h1>Search</h1>
    <form method="get" action="/search">
      <input name="q" placeholder="Search products...">
      <button type="submit">Search</button>
    </form>"""
    if q:
        body += "<p class='flag'>Reflected XSS: /search?q=&lt;script&gt;alert(1)&lt;/script&gt;</p>"
    return page("Search", body)


@app.route("/blog", methods=["GET", "POST"])
def blog():
    conn = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        content = request.form.get("content", "")
        conn.execute("INSERT INTO comments (user_id,author,content,created_at) VALUES (?,?,?,?)",
                     (0, author, content, datetime.datetime.utcnow().isoformat()))  # VULN stored
        conn.commit()
        conn.close()
        return redirect("/blog")

    rows = conn.execute("SELECT * FROM comments ORDER BY id DESC").fetchall()
    conn.close()
    items = "".join(
        f"<div class='card'><b>{r['author']}</b> <small>{r['created_at']}</small>"
        f"<p>{r['content']}</p></div>" for r in rows   # VULN: unescaped render
    )
    return page("Blog", f"""
    <h1>Community blog</h1>
    <div class="card">
      <form method="post" action="/blog">
        <label>Name</label><input name="author">
        <label>Comment</label><textarea name="content" rows="3"></textarea>
        <button type="submit">Post</button>
      </form>
    </div>
    {items}
    """)


@app.route("/domxss")
def domxss():
    return page("DOM XSS", """
    <h1>Profile greeting (DOM)</h1>
    <div class="card"><p>Ismingizni URL hash'ida bering: <code>/domxss#Ism</code></p>
    <h3 id="out">...</h3></div>
    <script>
      var n = decodeURIComponent(location.hash.substring(1));
      if (n) { document.getElementById('out').innerHTML = 'Salom, ' + n; }
    </script>
    """)


# ---------------------------- FILES ----------------------------------
@app.route("/download")
def download():
    name = request.args.get("file", "readme.txt")
    path = os.path.realpath(os.path.join(LAB_DIR, name))     # VULN: traversal
    if not path.startswith(BASE_DIR):
        abort(403)
    if not os.path.isfile(path):
        return page("Download", f"<h1>File not found</h1><p>{name}</p>"), 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@app.route("/files/")
def files_index():
    entries = sorted(os.listdir(LAB_DIR))
    rows = "".join(
        f"<tr><td><a href='/download?file={e}'>{e}</a></td>"
        f"<td>{os.path.getsize(os.path.join(LAB_DIR, e))} bytes</td></tr>"
        for e in entries
    )
    # VULN: directory listing
    return page("Files", f"""
    <h1>Index of /lab_files/</h1><table>
    <tr><th>Name</th><th>Size</th></tr>{rows}</table>
    <p>EJPT{dir_listing_20}</p>""")


@app.route("/page")
def lfi():
    name = request.args.get("name", "about")
    filename = name if name.endswith((".txt", ".html", ".ini", ".py", ".sql", ".bak")) else name + ".html"
    path = os.path.realpath(os.path.join(LAB_DIR, filename))   # VULN: LFI
    if not path.startswith(BASE_DIR):
        abort(403)
    if not os.path.isfile(path):
        return page("Page", f"<h1>Page not found</h1><p>{name}</p>"), 404
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    return page("Page", f"<h1>Page: {filename}</h1><div class='card'><pre>{content}</pre></div>")


@app.route("/backups/")
def backups_index():
    entries = sorted(os.listdir(BACKUP_DIR))
    rows = "".join(
        f"<tr><td><a href='/backups/{e}'>{e}</a></td>"
        f"<td>{os.path.getsize(os.path.join(BACKUP_DIR, e))} bytes</td></tr>"
        for e in entries
    )
    return page("Backups", f"""
    <h1>Index of /backups/</h1><table>
    <tr><th>File</th><th>Size</th></tr>{rows}</table>
    <p>EJPT{backup_exposure_21}</p>""")


@app.route("/backups/<path:name>")
def backups_file(name):
    return send_from_directory(BACKUP_DIR, name, as_attachment=False)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return page("Upload", """
        <h1>File upload</h1><div class="card">
        <form method="post" action="/upload" enctype="multipart/form-data">
          <input type="file" name="file"><button type="submit">Upload</button>
        </form>
        <p>Uploaded files are served from <code>/uploads/&lt;name&gt;</code></p></div>""")

    f = request.files.get("file")
    if not f or f.filename == "":
        return page("Upload", "<h1>No file</h1>"), 400
    safe_name = os.path.basename(f.filename)      # VULN: no extension/MIME validation
    dest = os.path.join(UPLOAD_DIR, safe_name)
    f.save(dest)
    return page("Upload", f"""<h1>Uploaded</h1>
    <div class='card'><p>Saved as <code>{safe_name}</code></p>
    <p><a href='/uploads/{safe_name}'>/uploads/{safe_name}</a></p>
    <p>EJPT{upload_bypass_22}</p></div>""")


@app.route("/uploads/<path:name>")
def uploaded(name):
    return send_from_directory(UPLOAD_DIR, name)


# ---------------------------- CSRF -----------------------------------
@app.route("/settings/email", methods=["GET", "POST"])
def settings_email():
    if request.method == "GET":
        return page("Settings", """
        <h1>Change email</h1><div class="card">
        <form method="post" action="/settings/email">
          <label>User ID</label><input name="uid" value="8">
          <label>New email</label><input name="email">
          <button type="submit">Save</button>
        </form>
        <p>No CSRF token is used.</p></div>""")

    uid = request.form.get("uid", "8")
    email = request.form.get("email", "")
    conn = get_db()
    conn.execute("UPDATE users SET email=? WHERE id=?", (email, uid))   # VULN: no CSRF token
    conn.commit()
    conn.close()
    return page("Settings", f"<h1>Email updated</h1><p>User {uid} -> {email}</p>"
                            f"<p>EJPT{csrf_email_13}</p>")


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if request.method == "GET":
        return page("Transfer", """
        <h1>Money transfer</h1><div class="card">
        <form method="post" action="/transfer">
          <label>From user ID</label><input name="from_uid" value="8">
          <label>To user ID</label><input name="to_uid" value="1">
          <label>Amount</label><input name="amount" value="10">
          <button type="submit">Transfer</button>
        </form></div>""")

    f_uid = request.form.get("from_uid", "8")
    t_uid = request.form.get("to_uid", "1")
    try:
        amount = float(request.form.get("amount", "0"))
    except ValueError:
        amount = 0.0
    conn = get_db()
    conn.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, f_uid))
    conn.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, t_uid))
    conn.commit()
    conn.close()
    return page("Transfer", f"<h1>Transfer done</h1><p>{amount} from {f_uid} to {t_uid}</p>"
                            f"<p>EJPT{csrf_transfer_14}</p>")


# ---------------------------- REDIRECT -------------------------------
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    return redirect(url)     # VULN: open redirect


# ---------------------------- ADMIN ----------------------------------
def _admin_body():
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    flags = conn.execute("SELECT * FROM flags ORDER BY id").fetchall()
    logs = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 30").fetchall()
    notes = conn.execute("SELECT * FROM notes ORDER BY id").fetchall()
    challenges = conn.execute("SELECT * FROM challenges").fetchall()
    conn.close()

    urows = "".join(
        f"<tr><td>{u['id']}</td><td>{u['username']}</td><td><code>{u['password_md5']}</code></td>"
        f"<td>{u['role']}</td><td>{u['email']}</td><td>{u['api_key']}</td>"
        f"<td>{u['credit_card']}</td></tr>" for u in users)

    frows = "".join(
        f"<tr><td>{x['id']}</td><td class='flag'>{x['code']}</td><td>{x['name']}</td>"
        f"<td>{x['category']}</td><td>{x['difficulty']}</td><td>{x['points']}</td></tr>"
        for x in flags)

    lrows = "".join(
        f"<tr><td>{l['id']}</td><td>{l['ts']}</td><td>{l['ip']}</td><td>{l['method']}</td>"
        f"<td>{l['path']}</td><td>{l['message']}</td></tr>" for l in logs)

    nrows = "".join(
        f"<tr><td>{n['id']}</td><td>{n['user_id']}</td><td>{n['title']}</td>"
        f"<td>{n['content']}</td><td>{'yes' if n['is_private'] else 'no'}</td></tr>"
        for n in notes)

    crows = "".join(
        f"<tr><td>{c['id']}</td><td>{c['name']}</td><td><code>{c['endpoint']}</code></td>"
        f"<td>{c['method']}</td><td>{c['difficulty']}</td></tr>" for c in challenges)

    return f"""
    <h1>Administration Panel</h1>
    <div class="card"><p>EJPT{{bac_admin_16}}</p>
    <p><b>Config in use:</b> JWT secret <code>{JWT_SECRET}</code>,
    master API key <code>{MASTER_API_KEY}</code></p></div>

    <h2>Users ({len(users)})</h2>
    <table><tr><th>ID</th><th>User</th><th>MD5</th><th>Role</th><th>Email</th>
    <th>API key</th><th>Card</th></tr>{urows}</table>

    <h2>Secret notes</h2>
    <table><tr><th>ID</th><th>User</th><th>Title</th><th>Content</th><th>Private</th></tr>
    {nrows}</table>

    <h2>Flags ({len(flags)})</h2>
    <table><tr><th>ID</th><th>Flag</th><th>Name</th><th>Category</th><th>Diff</th>
    <th>Points</th></tr>{frows}</table>

    <h2>Challenges ({len(challenges)})</h2>
    <table><tr><th>ID</th><th>Name</th><th>Endpoint</th><th>Method</th><th>Diff</th></tr>
    {crows}</table>

    <h2>Application logs (last 30)</h2>
    <table><tr><th>ID</th><th>Time</th><th>IP</th><th>Method</th><th>Path</th>
    <th>Message</th></tr>{lrows}</table>

    <p class="flag">EJPT{{master_55}}</p>
    """


@app.route("/admin")
def admin():
    return page("Admin", _admin_body())      # VULN: no auth


@app.route("/administrator.php")
def hidden_admin():
    return page("Administrator", _admin_body() + "<p>EJPT{hidden_admin_38}</p>")


@app.route("/challenges")
def challenges_page():
    conn = get_db()
    rows = conn.execute("SELECT * FROM challenges ORDER BY id").fetchall()
    conn.close()
    html = "".join(
        f"<tr><td>{r['id']}</td><td>{r['name']}</td><td><code>{r['endpoint']}</code></td>"
        f"<td>{r['method']}</td><td><span class='badge {str(r['difficulty']).lower()}'>"
        f"{r['difficulty']}</span></td><td>{r['description']}</td><td>{r['expected']}</td></tr>"
        for r in rows)
    return page("Challenges", f"""
    <h1>Challenge list ({len(rows)})</h1>
    <table><tr><th>ID</th><th>Name</th><th>Endpoint</th><th>Method</th>
    <th>Difficulty</th><th>Description</th><th>Expected behavior</th></tr>
    {html}</table>""")


# ---------------------------- SERVER INFO ---------------------------
@app.route("/server-info")
def server_info():
    env = {k: v for k, v in os.environ.items() if k.upper() in (
        "PATH", "HOME", "USER", "SHELL", "PYTHONPATH", "FLASK_ENV", "PWD")}
    return page("Server info", f"""
    <h1>Server information</h1>
    <div class="card"><pre>
Host      : {request.host}
IP        : {request.remote_addr}
Server    : Werkzeug/2.3.7 Python/3.11
Framework : Flask 2.3.3
OS        : {os.uname().sysname} {os.uname().release}
CWD       : {os.getcwd()}
App file  : {os.path.abspath(__file__)}
DB file   : {DB_PATH}
Debug     : {DEBUG_MODE}
Secret key: {SECRET_KEY}
</pre></div>
    <h3>Environment</h3><pre>{json.dumps(env, indent=2)}</pre>
    <p>EJPT{{server_banner_43}} / EJPT{{info_disclosure_19}}</p>""")


@app.route("/debug")
def debug_page():
    return page("Debug", f"""
    <h1>Debug</h1>
    <div class="card"><pre>
JWT_SECRET     = {JWT_SECRET}
JWT_WEAK       = {JWT_WEAK_SECRET}
MASTER_API_KEY = {MASTER_API_KEY}
ADMIN_USER     = {ADMIN_USER}
ADMIN_PASS     = {ADMIN_PASS}
DB_USER        = {DB_USER}
DB_PASS        = {DB_PASS}
SECRET_KEY     = {SECRET_KEY}
</pre></div><p>EJPT{{misconfig_31}}</p>""")


@app.route("/api/config")
def api_config():
    return jsonify({
        "status": "ok",
        "debug": True,
        "database": {"path": DB_PATH, "user": DB_USER, "password": DB_PASS},
        "jwt": {"secret": JWT_SECRET, "algorithm": "HS256", "expiry": None},
        "admin": {"username": ADMIN_USER, "password": ADMIN_PASS},
        "master_api_key": MASTER_API_KEY,
        "flag": "EJPT{hardcoded_creds_25}",
    })


@app.route("/api/debug/env")
def api_debug_env():
    env = dict(os.environ)
    env["LAB_JWT_SECRET"] = JWT_SECRET
    env["LAB_DB_PASSWORD"] = DB_PASS
    env["LAB_FLAG"] = "EJPT{config_file_48}"
    return jsonify({"environment": env, "cwd": os.getcwd(), "python": sys_version()})


def sys_version():
    import platform
    return platform.python_version()


# ---------------------------- API v1 (weak auth) --------------------
def api_auth_ok():
    # VULN: key in header OR query string OR master key fallback
    key = request.headers.get("X-API-Key") or request.args.get("api_key", "")
    if key == MASTER_API_KEY:
        return True
    if key and key.startswith("AKIA-LAB-"):
        return True
    if request.args.get("debug") == "1":       # VULN: debug bypass
        return True
    return False


@app.route("/api/v1/users")
def api_v1_users():
    if not api_auth_ok():
        return jsonify({"error": "unauthorized",
                        "hint": "provide X-API-Key or ?api_key="}), 401
    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()
    return jsonify({
        "count": len(rows),
        "users": [dict(r) for r in rows],      # VULN: excessive data exposure
        "flag": "EJPT{excessive_data_29}",
    })


@app.route("/api/v1/users/<int:uid>")
def api_v1_user(uid):
    if not api_auth_ok():
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/v1/orders")
def api_v1_orders():
    if not api_auth_ok():
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    rows = conn.execute("SELECT * FROM orders").fetchall()
    conn.close()
    return jsonify({"orders": [dict(r) for r in rows], "flag": "EJPT{card_data_50}"})


@app.route("/api/v1/notes")
def api_v1_notes():
    conn = get_db()
    rows = conn.execute("SELECT * FROM notes").fetchall()
    conn.close()
    return jsonify({"notes": [dict(r) for r in rows]})


@app.route("/api/v1/delete_user")
def api_delete_user():
    # VULN: destructive action over GET + weak auth
    if not api_auth_ok():
        return jsonify({"error": "unauthorized"}), 401
    uid = request.args.get("id", "")
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    return jsonify({"deleted": uid, "flag": "EJPT{http_method_33}"})


@app.route("/api/v1/admin/reset", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def api_admin_reset():
    # VULN: accepts every method, no auth at all
    conn = get_db()
    conn.execute("UPDATE users SET balance = 1000 WHERE role='user'")
    conn.commit()
    conn.close()
    return jsonify({"status": "balances reset", "method": request.method,
                    "flag": "EJPT{no_headers_34}"})


@app.route("/api/v1/me")
def api_v1_me():
    token = request.args.get("token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    conn = get_db()
    row = conn.execute("SELECT * FROM api_tokens WHERE token=?", (token,)).fetchone()  # no expiry
    conn.close()
    if not row:
        return jsonify({"error": "invalid token"}), 401
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
    conn.close()
    return jsonify({"user": dict(user) if user else None, "flag": "EJPT{broken_auth_44}"})


# ---------------------------- API: legacy ---------------------------
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    u = data.get("username", "")
    p = data.get("password", "")

    # VULN: hardcoded master credential + plaintext comparison
    if u == ADMIN_USER and (p == ADMIN_PASS or p == "master"):
        row = {"id": 1, "username": "admin", "role": "admin"}
    else:
        conn = get_db()
        r = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        conn.close()
        if not r or (r["password_md5"] != md5(p) and p != r["password_md5"]):
            return jsonify({"error": "invalid credentials"}), 401
        row = {"id": r["id"], "username": r["username"], "role": r["role"]}

    token = b64u(f"{row['id']}|{row['username']}|{time.time()}")   # VULN: no expiry
    conn = get_db()
    conn.execute("INSERT INTO api_tokens (user_id,token,created_at) VALUES (?,?,?)",
                 (row["id"], token, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    resp = jsonify({"ok": True, "user": row, "token": token,
                    "flag": "EJPT{weak_session_17}"})
    resp.set_cookie("uid", str(row["id"]), httponly=False)
    resp.set_cookie("role", row["role"], httponly=False)
    resp.set_cookie("auth", f"{row['id']}:{row['role']}", httponly=False)
    return resp


@app.route("/api/user/<int:uid>")
def api_user(uid):
    # VULN: IDOR, no authentication whatsoever
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/users")
def api_users():
    conn = get_db()
    rows = conn.execute("SELECT id,username,password_md5,password_sha1,email,role,api_key "
                        "FROM users").fetchall()
    conn.close()
    return jsonify({"users": [dict(r) for r in rows], "flag": "EJPT{hash_exposure_24}"})


@app.route("/api/admin/users")
def api_admin_users():
    conn = get_db()          # VULN: broken access control
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return jsonify({"users": [dict(r) for r in rows], "flag": "EJPT{bac_admin_16}"})


@app.route("/api/check-user")
def api_check_user():
    username = request.args.get("username", "")
    conn = get_db()
    row = conn.execute("SELECT id,role FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if row:
        return jsonify({"exists": True, "role": row["role"],
                        "message": "User found", "flag": "EJPT{user_enum_40}"})
    return jsonify({"exists": False, "message": "No user with this username"})


@app.route("/api/otp/send")
def api_otp_send():
    username = request.args.get("user", "")
    code = "4821" if username == "admin" else "".join(random.choice(string.digits) for _ in range(4))
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO otp (username,code) VALUES (?,?)", (username, code))
    conn.commit()
    conn.close()
    return jsonify({"sent": True, "user": username,
                    "hint": "OTP is 4 digits, unlimited attempts"})


@app.route("/api/otp/verify")
def api_otp_verify():
    username = request.args.get("user", "")
    code = request.args.get("code", "")
    conn = get_db()
    row = conn.execute("SELECT code FROM otp WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "otp not sent"}), 400
    # VULN: no rate limiting / lockout
    if code == row["code"]:
        return jsonify({"valid": True, "flag": "EJPT{rate_limit_37}"})
    return jsonify({"valid": False, "attempts": "unlimited"})


@app.route("/api/profile/update", methods=["POST"])
def api_profile_update():
    data = request.get_json(silent=True) or {}
    uid = data.get("uid")
    if uid is None:
        return jsonify({"error": "uid required"}), 400
    allowed_fields = ["email", "full_name", "balance", "role", "is_active", "api_key"]
    sets, vals = [], []
    for f in allowed_fields:                 # VULN: mass assignment (role allowed)
        if f in data:
            sets.append(f"{f}=?")
            vals.append(data[f])
    if not sets:
        return jsonify({"error": "nothing to update"}), 400
    vals.append(uid)
    conn = get_db()
    conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return jsonify({"updated": True, "user": dict(row) if row else None,
                    "flag": "EJPT{mass_assign_36}"})


@app.route("/api/ssrf-check")
def api_ssrf_check():
    # VULN: improper input handling - URL accepted, echoes back, no allowlist
    url = request.args.get("url", "")
    host = ""
    try:
        host = url.split("//", 1)[1].split("/", 1)[0]
    except Exception:
        host = url
    return jsonify({"target": url, "resolved_host": host,
                    "internal_hint": "http://127.0.0.1:2004/api/config",
                    "flag": "EJPT{api_ssrf_47}"})


# ---------------------------- IDOR resources ------------------------
@app.route("/documents/<int:did>")
def documents(did):
    conn = get_db()
    row = conn.execute("SELECT * FROM documents WHERE id=?", (did,)).fetchone()   # VULN: IDOR
    conn.close()
    if not row:
        return page("Document", "<h1>Not found</h1>"), 404
    return page("Document", f"""
    <h1>Document #{row['id']}</h1>
    <div class='card'><p><b>{row['filename']}</b> ({row['classification']})</p>
    <pre>{row['content']}</pre></div>""")


@app.route("/invoice/<int:iid>")
def invoice(iid):
    conn = get_db()
    row = conn.execute("SELECT * FROM invoices WHERE id=?", (iid,)).fetchone()    # VULN: IDOR
    conn.close()
    if not row:
        return page("Invoice", "<h1>Invoice not found</h1>"), 404
    return page("Invoice", f"""
    <h1>Invoice #{row['id']}</h1>
    <div class='card'><p>Reference: {row['reference']}</p>
    <p>User: {row['user_id']}</p><p>Amount: {row['amount']}</p>
    <p>Paid: {'yes' if row['paid'] else 'no'}</p>
    <p>EJPT{{idor_invoice_07}}</p></div>""")


# ---------------------------- JWT API -------------------------------
@app.route("/api/jwt/login", methods=["POST"])
def jwt_login():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    u = data.get("username", "")
    p = data.get("password", "")
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    conn.close()
    if not row or row["password_md5"] != md5(p):
        return jsonify({"error": "invalid credentials"}), 401
    token = jwt_encode({"uid": row["id"], "username": row["username"],
                        "role": row["role"], "iat": int(time.time())})
    return jsonify({"token": token, "type": "Bearer"})


@app.route("/api/jwt/me", methods=["GET", "POST"])
def jwt_me():
    data = request.get_json(silent=True) or {}
    token = data.get("token") or request.headers.get("Authorization", "").replace("Bearer ", "") \
        or request.args.get("token", "")
    payload = jwt_decode(token)
    if not payload:
        return jsonify({"error": "invalid token"}), 401
    uid = payload.get("uid")
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None
    conn.close()
    return jsonify({
        "payload": payload,
        "user": dict(row) if row else None,
        "is_admin": payload.get("role") == "admin",
        "flag": "EJPT{jwt_alg_none_26}" if payload.get("role") == "admin" else None,
    })


# ---------------------------- GRAPHQL -------------------------------
GQL_TYPES = {
    "User": ["id", "username", "password_md5", "password_sha1", "email", "role",
             "full_name", "api_key", "ssn", "credit_card", "balance"],
    "Note": ["id", "user_id", "title", "content", "is_private"],
    "Order": ["id", "user_id", "product", "amount", "status", "card_number"],
    "Flag": ["id", "code", "name", "category", "difficulty", "points"],
    "Document": ["id", "user_id", "filename", "content", "classification"],
}


def gql_introspection():
    return {
        "data": {"__schema": {
            "queryType": {"name": "Query"},
            "mutationType": None,
            "subscriptionType": None,
            "types": [{"kind": "OBJECT", "name": t,
                       "fields": [{"name": f, "args": [], "type": {"kind": "SCALAR", "name": "String"}}
                                  for f in fields]}
                      for t, fields in GQL_TYPES.items()],
            "directives": [],
        }},
        "flag": "EJPT{graphql_42}",
    }


GQL_TABLES = {
    "users": ("User", "SELECT * FROM users"),
    "user": ("User", "SELECT * FROM users WHERE id = {}"),
    "notes": ("Note", "SELECT * FROM notes"),
    "orders": ("Order", "SELECT * FROM orders"),
    "flags": ("Flag", "SELECT * FROM flags"),
    "documents": ("Document", "SELECT * FROM documents"),
}


@app.route("/graphql", methods=["GET", "POST", "OPTIONS"])
def graphql():
    if request.method == "OPTIONS":
        return ("", 204)
    if request.method == "GET" and not request.args.get("query"):
        return page("GraphQL", """
        <h1>GraphQL endpoint</h1><div class="card">
        <p>POST JSON <code>{"query": "{ users { id username password_md5 } }"}</code></p>
        <p>Introspection: <code>{"query": "{ __schema { types { name } } }"}</code></p>
        <p>Introspection is enabled and no authentication is required.</p></div>""")

    payload = request.get_json(silent=True) or request.form.to_dict() or {}
    query = payload.get("query") or request.args.get("query", "")
    if not query:
        return jsonify({"errors": [{"message": "must provide query string"}]}), 400

    if "__schema" in query or "__type" in query:
        # VULN: introspection enabled without auth
        return jsonify(gql_introspection())

    m = re.search(r"\{\s*(\w+)\s*(?:\([^)]*\))?\s*\{([^}]*)\}", query)
    if not m:
        return jsonify({"errors": [{"message": "cannot parse query"}]}), 400

    root, field_str = m.group(1), m.group(2)
    fields = [f.strip() for f in re.split(r"[,\s]+", field_str) if f.strip()]
    if root not in GQL_TABLES:
        return jsonify({"errors": [{"message": f"unknown field '{root}'"}]}), 400

    _, sql = GQL_TABLES[root]
    if "{}" in sql:
        idm = re.search(r"id\s*:\s*(\d+)", query)
        if not idm:
            return jsonify({"errors": [{"message": "id argument required"}]}), 400
        sql = sql.format(idm.group(1))

    conn = get_db()
    try:
        rows = conn.execute(sql).fetchall()
    except Exception as e:
        conn.close()
        return jsonify({"errors": [{"message": str(e)}]}), 500
    conn.close()

    if not fields or fields == ["__typename"]:
        fields = GQL_TYPES[GQL_TABLES[root][0]]

    result = []
    for r in rows:
        item = {}
        for f in fields:
            try:
                item[f] = r[f]
            except Exception:
                item[f] = None
        result.append(item)

    return jsonify({"data": {root: result}})


# ---------------------------- HEALTH --------------------------------
@app.route("/health")
def health():
    return jsonify({"status": "up", "port": 2004, "time": datetime.datetime.utcnow().isoformat()})


# ---------------------------------------------------------------------
# BOOTSTRAP
# ---------------------------------------------------------------------
init_db()

if __name__ == "__main__":
    print("=" * 62)
    print(" eJPT LAB listening on http://0.0.0.0:2004")
    print(" DEBUG_MODE =", DEBUG_MODE, "(export LAB_DEBUG=1 to enable)")
    print(" DB:", DB_PATH)
    print("=" * 62)
    app.run(host="0.0.0.0", port=2004, threaded=True, debug=DEBUG_MODE)
