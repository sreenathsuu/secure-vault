# config.py
import os

DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "port":     int(os.getenv("DB_PORT", "3306")),
    "database": os.getenv("DB_NAME",     "securevault"),
    "user":     os.getenv("DB_USER",     "root"),
    "password": os.getenv("DB_PASSWORD", "sree89"),
}

SECRET_KEY      = os.getenv("SECRET_KEY", "change-me-in-production")
TOKEN_EXPIRE_H  = int(os.getenv("TOKEN_EXPIRE_H", "8"))
UPLOAD_FOLDER   = os.getenv("UPLOAD_FOLDER", "./vault")
MAX_CONTENT_MB  = int(os.getenv("MAX_CONTENT_MB", "50"))
