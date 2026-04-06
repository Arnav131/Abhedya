"""
Django settings for Abhedya API.

Deployment-ready configuration using environment variables.
- Dev: SQLite + DEBUG=True (just create a .env from .env.example)
- Prod: PostgreSQL + DEBUG=False + gunicorn (set DATABASE_URL, SECRET_KEY in env)
"""

import os
from pathlib import Path
from datetime import timedelta

from decouple import config, Csv
import dj_database_url

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent

# ──────────────────────────────────────────────
# Security
# ──────────────────────────────────────────────
SECRET_KEY = config("SECRET_KEY", default="django-insecure-dev-key-change-me-in-production")
DEBUG = config("DEBUG", default=True, cast=bool)
ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="localhost,127.0.0.1", cast=Csv())

# ──────────────────────────────────────────────
# Application definition
# ──────────────────────────────────────────────
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "rest_framework",
    "corsheaders",
    # Local
    "vault",
    "ai_engine",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",  # Static files in production
    "corsheaders.middleware.CorsMiddleware",        # CORS — must be before CommonMiddleware
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "abhedya_api.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "abhedya_api.wsgi.application"

# ──────────────────────────────────────────────
# Database
# Reads DATABASE_URL from env for production (Postgres).
# Falls back to SQLite for local development.
# ──────────────────────────────────────────────
DATABASE_URL = config("DATABASE_URL", default="")

if DATABASE_URL:
    DATABASES = {
        "default": dj_database_url.parse(DATABASE_URL, conn_max_age=600),
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

# ──────────────────────────────────────────────
# Password validation
# ──────────────────────────────────────────────
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ──────────────────────────────────────────────
# Internationalization
# ──────────────────────────────────────────────
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ──────────────────────────────────────────────
# Static files (WhiteNoise for production)
# ──────────────────────────────────────────────
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# ──────────────────────────────────────────────
# Django REST Framework
# ──────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
}

# ──────────────────────────────────────────────
# Simple JWT
# ──────────────────────────────────────────────
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": False,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# ──────────────────────────────────────────────
# CORS
# ──────────────────────────────────────────────
CORS_ALLOWED_ORIGINS = config(
    "CORS_ALLOWED_ORIGINS",
    default="http://localhost:3000,http://localhost:5173,https://abhedya-ikjj.onrender.com",
    cast=Csv(),
)
CORS_ALLOW_CREDENTIALS = True

# ──────────────────────────────────────────────
# Default primary key field type
# ──────────────────────────────────────────────
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ──────────────────────────────────────────────
# Production hardening (applied when DEBUG=False)
# ──────────────────────────────────────────────
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    X_FRAME_OPTIONS = "DENY"
    SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=True, cast=bool)
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ──────────────────────────────────────────────
# Honeypot Deception Engine (Phase 3)
# ──────────────────────────────────────────────
# Auto-generates fake decoy secrets via local LLM at registration time.
# Priority: Ollama → HuggingFace Transformers → Deterministic Fallback
HONEYPOT = {
    # Master switch — set False to disable honeypot generation entirely
    "ENABLED": config("HONEYPOT_ENABLED", default=True, cast=bool),
    # Enable local LLM generation for registration when available.
    "USE_LLM_ON_REGISTRATION": config("HONEYPOT_USE_LLM_ON_REGISTRATION", default=True, cast=bool),
    # Backend: "ollama" (recommended), "auto", "transformers", "fallback"
    "LLM_BACKEND": config("HONEYPOT_LLM_BACKEND", default="ollama"),
    # Ollama settings (used when backend is "auto" or "ollama")
    "OLLAMA_BASE_URL": config("OLLAMA_BASE_URL", default="http://localhost:11434"),
    "OLLAMA_MODEL": config("OLLAMA_MODEL", default="llama3"),
    "OLLAMA_TIMEOUT": config("OLLAMA_TIMEOUT", default=30, cast=int),
    # HuggingFace Transformers settings (used when backend is "auto" or "transformers")
    "TRANSFORMERS_MODEL": config("HONEYPOT_TRANSFORMERS_MODEL", default="distilgpt2"),
    # Number of decoy passwords to generate per user
    "DECOY_PASSWORDS_COUNT": config("HONEYPOT_DECOY_PASSWORDS", default=4, cast=int),
}

# ──────────────────────────────────────────────
# Honeypot Breach Alerts (Phase 4)
# ──────────────────────────────────────────────
HONEYPOT_ALERT = {
    # Master switch for SMTP breach alerts
    "ENABLED": config("HONEYPOT_ALERT_ENABLED", default=True, cast=bool),
    # SMTP transport
    "SMTP_HOST": config("SMTP_HOST", default="smtp.gmail.com"),
    "SMTP_PORT": config("SMTP_PORT", default=587, cast=int),
    "SMTP_EMAIL": config("SMTP_EMAIL", default=""),
    "SMTP_PASSWORD": config("SMTP_PASSWORD", default=""),
    "SMTP_FROM_NAME": config("SMTP_FROM_NAME", default="Abhedya Security"),
    "SMTP_USE_TLS": config("SMTP_USE_TLS", default=True, cast=bool),
    "SMTP_TIMEOUT": config("SMTP_TIMEOUT", default=30, cast=int),
    # Max alerts per user per hour (used by alert API module defaults)
    "ALERT_RATE_LIMIT": config("ALERT_RATE_LIMIT", default=5, cast=int),
}

