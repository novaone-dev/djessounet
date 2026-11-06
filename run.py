"""Backend FastAPI de DjessouNet - Version Finale"""

import os
import hmac
import base64
import hashlib
import secrets
import asyncio
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

import jwt
import psycopg
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Query, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, field_validator

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_DAYS = 7

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL est absent du fichier .env")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET est absent du fichier .env")

async def keep_awake():
    url = "https://djessounet.onrender.com/api/status"
    while True:
        await asyncio.sleep(120)
        try:
            urllib.request.urlopen(url, timeout=10)
        except Exception:
            pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(keep_awake())
    yield
    task.cancel()

app = FastAPI(title="DjessouNet API", version="6.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    print(f"Erreur serveur sur {request.method} {request.url.path}: {exc!r}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Le serveur est momentanément indisponible."},
    )

required_bearer = HTTPBearer()
optional_bearer = HTTPBearer(auto_error=False)

def get_connection():
    return psycopg.connect(DATABASE_URL, connect_timeout=15)

# -------------------------- SÉCURITÉ --------------------------

def hash_password(password: str) -> str:
    iterations = 600_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, AttributeError):
        return False

def create_access_token(user_id) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": str(user_id), "iat": now, "exp": now + timedelta(days=JWT_DAYS)},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if not payload.get("sub"):
            raise HTTPException(status_code=401, detail="Token invalide.")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expirée.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide.")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(required_bearer)):
    payload = decode_token(credentials.credentials)
    return {"user_id": payload["sub"]}

def get_optional_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_bearer)):
    if not credentials:
        return None
    try:
        payload = decode_token(credentials.credentials)
        return {"user_id": payload["sub"]}
    except HTTPException:
        return None

def _create_notification(cur, recipient_id, sender_id, notif_type: str, post_id=None) -> None:
    if str(recipient_id) == str(sender_id):
        return
    cur.execute(
        "INSERT INTO notifications (recipient_id, sender_id, type, post_id, is_read, created_at) "
        "VALUES (%s, %s, %s, %s, FALSE, NOW())",
        (recipient_id, sender_id, notif_type, post_id),
    )

# -------------------------- MODÈLES --------------------------

class RegisterRequest(BaseModel):
    nom: str = Field(min_length=1, max_length=100)
    prenom: str = Field(min_length=1, max_length=100)
    classe: str = Field(min_length=1, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    ticket: Optional[str] = None

    @field_validator('email')
    @classmethod
    def check_gmail(cls, v: str):
        if not v.lower().endswith('@gmail.com'):
            raise ValueError('Seules les adresses @gmail.com sont acceptées.')
        return v.lower()

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ProfileUpdateRequest(BaseModel):
    nom: Optional[str] = Field(default=None, max_length=100)
    prenom: Optional[str] = Field(default=None, max_length=100)
    classe: Optional[str] = Field(default=None, max_length=50)
    avatar_url: Optional[str] = Field(default=None, max_length=1_000_000)
    neighborhood: Optional[str] = None
    relationship_status: Optional[str] = None
    favorite_subjects: Optional[str] = None
    favorite_teacher: Optional[str] = None
    interests: Optional[str] = None

class AdminLoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)

class AdminCreateUserRequest(BaseModel):
    nom: str = Field(min_length=1, max_length=100)
    prenom: str = Field(min_length=1, max_length=100)
    classe: str = Field(min_length=1, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class AdminGenerateTicketsRequest(BaseModel):
    count: int = Field(default=10, ge=1, le=500)

class CreatePostRequest(BaseModel):
    media_url: str = Field(min_length=1, max_length=1_000_000)
    media_type: str = Field(pattern="^(image|video)$")
    title: str = Field(default="", max_length=120)
    description: str = Field(default="", max_length=300)

class CommentRequest(BaseModel):
    content: str = Field(min_length=1, max_length=500)

def require_admin(x_admin_password: Optional[str] = Header(default=None, alias="X-Admin-Password")):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=503, detail="ADMIN_PASSWORD n'est pas configuré.")
    if not x_admin_password or not hmac.compare_digest(x_admin_password, ADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="Mot de passe administrateur invalide.")
    return True

# -------------------------- ROUTES DE BASE --------------------------

@app.api_route("/api/status", methods=["GET", "HEAD"])
def api_status():
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
        return {"status": "ok", "database": "connected"}
    except Exception:
        raise HTTPException(status_code=503, detail="Impossible de joindre la base de données.")

# -------------------------- AUTHENTIFICATION --------------------------

@app.post("/api/register", status_code=201)
def register(data: RegisterRequest):
    email = str(data.email).strip().lower()
    ticket = data.ticket.strip() if data.ticket else None

    try:
        with get_connection() as conn, conn.cursor() as cur:
            if ticket:
                cur.execute("SELECT is_used FROM tickets WHERE code = %s FOR UPDATE", (ticket,))
                ticket_row = cur.fetchone()
                if not ticket_row or ticket_row[0]:
                    raise HTTPException(status_code=400, detail="Ticket invalide.")

            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Email déjà utilisé.")

            cur.execute(
                "INSERT INTO users (nom, prenom, classe, email, password, ticket_code) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (data.nom.strip(), data.prenom.strip(), data.classe.strip(), email, hash_password(data.password), ticket),
            )
            user_id = cur.fetchone()[0]

            if ticket:
                cur.execute("UPDATE tickets SET is_used = TRUE WHERE code = %s", (ticket,))

        return {"status": "ok", "message": "Inscription réussie.", "user_id": str(user_id)}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Erreur lors de l'inscription.")

@app.post("/api/login")
def login(data: LoginRequest):
    email = str(data.email).strip().lower()
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT id, nom, prenom, classe, password, avatar_url FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            if user:
                cur.execute("UPDATE users SET last_seen = NOW() WHERE id = %s", (user[0],))
    except Exception:
        raise HTTPException(status_code=503, detail="Impossible de se connecter.")

    if not user or not verify_password(data.password, user[4]):
        raise HTTPException(status_code=401, detail="E-mail ou mot de passe incorrect.")
    return {
        "status": "ok",
        "token": create_access_token(user[0]),
        "user": {"id": str(user[0]), "nom": user[1], "prenom": user[2], "classe": user[3], "avatar_url": user[5]},
    }

# -------------------------- PROFILS --------------------------

@app.get("/api/me")
def me(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE users SET last_seen = NOW() WHERE id = %s", (current_user["user_id"],))
        cur.execute("SELECT id, nom, prenom, classe, email, avatar_url, relationship_status, neighborhood, favorite_subjects, favorite_teacher, interests FROM users WHERE id = %s", (current_user["user_id"],))
        user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Compte introuvable.")
    return {
        "id": str(user[0]), "nom": user[1], "prenom": user[2], "classe": user[3], "email": user[4],
        "avatar_url": user[5], "relationship_status": user[6], "neighborhood": user[7],
        "favorite_subjects": user[8], "favorite_teacher": user[9], "interests": user[10]
    }

@app.post("/api/users/me")
def update_my_profile(data: ProfileUpdateRequest, current_user: dict = Depends(get_current_user)):
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT nom, prenom, classe, avatar_url, neighborhood, relationship_status, favorite_subjects, favorite_teacher, interests FROM users WHERE id = %s", (current_user["user_id"],))
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="Compte introuvable.")

            nom = data.nom.strip() if data.nom is not None else user[0]
            prenom = data.prenom.strip() if data.prenom is not None else user[1]
            classe = data.classe.strip() if data.classe is not None else user[2]
            avatar = data.avatar_url if data.avatar_url is not None else user[3]
            neighborhood = data.neighborhood if data.neighborhood is not None else user[4]
            relationship = data.relationship_status if data.relationship_status is not None else user[5]
            subjects = data.favorite_subjects if data.favorite_subjects is not None else user[6]
            teacher = data.favorite_teacher if data.favorite_teacher is not None else user[7]
            interests = data.interests if data.interests is not None else user[8]

            if avatar and not avatar.startswith(("data:image/jpeg;base64,", "data:image/png;base64,", "data:image/webp;base64,")):
                raise HTTPException(status_code=400, detail="Format de photo invalide.")

            cur.execute(
                "UPDATE users SET nom=%s, prenom=%s, classe=%s, avatar_url=%s, neighborhood=%s, relationship_status=%s, favorite_subjects=%s, favorite_teacher=%s, interests=%s WHERE id=%s RETURNING id, nom, prenom, classe, avatar_url",
                (nom, prenom, classe, avatar, neighborhood, relationship, subjects, teacher, interests, current_user["user_id"])
            )
            row = cur.fetchone()
        return {"status": "ok", "message": "Profil mis à jour.", "user": {"id": str(row[0]), "nom": row[1], "prenom": row[2], "classe": row[3], "avatar_url": row[4]}}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Impossible de mettre à jour le profil.")

@app.get("/api/users")
def get_users(classe: Optional[str] = Query(default=None, max_length=50)):
    with get_connection() as conn, conn.cursor() as cur:
        if classe:
            cur.execute(
                "SELECT id, nom, prenom, classe, avatar_url FROM users WHERE TRIM(classe) ILIKE %s ORDER BY prenom, nom LIMIT 100",
                (f"%{classe.strip()}%",)
            )
        else:
            cur.execute("SELECT id, nom, prenom, classe, avatar_url FROM users ORDER BY prenom, nom LIMIT 100")
        rows = cur.fetchall()
    return [{"id": str(r[0]), "nom": r[1], "prenom": r[2], "classe": r[3], "avatar_url": r[4]} for r in rows]

@app.get("/api/users/search")
def search_users(q: str = Query(default="", max_length=100)):
    query = q.strip()
    if len(query) < 2:
        return []
    pattern = f"%{query}%"
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, nom, prenom, classe, avatar_url FROM users WHERE nom ILIKE %s OR prenom ILIKE %s OR classe ILIKE %s OR CONCAT(prenom, ' ', nom) ILIKE %s ORDER BY prenom, nom LIMIT 30",
            (pattern, pattern, pattern, pattern),
        )
        rows = cur.fetchall()
    return [{"id": str(r[0]), "nom": r[1], "prenom": r[2], "classe": r[3], "avatar_url": r[4]} for r in rows]

@app.get("/api/users/{user_id}")
def get_user_profile(
    user_id: str,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    uid = current_user["user_id"] if current_user else None
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, nom, prenom, classe, avatar_url, relationship_status, neighborhood, "
            "favorite_subjects, favorite_teacher, interests FROM users WHERE id = %s",
            (user_id,),
        )
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Profil introuvable.")

        cur.execute("SELECT COUNT(*) FROM subscriptions WHERE subscribed_to_id = %s", (user_id,))
        followers = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM subscriptions WHERE subscriber_id = %s", (user_id,))
        following = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM posts WHERE user_id = %s", (user_id,))
        posts_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM post_likes pl JOIN posts p ON p.id = pl.post_id WHERE p.user_id = %s", (user_id,))
        likes_received = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM comments c JOIN posts p ON p.id = c.post_id WHERE p.user_id = %s", (user_id,))
        comments_received = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM post_saves ps JOIN posts p ON p.id = ps.post_id WHERE p.user_id = %s", (user_id,))
        saves_received = cur.fetchone()[0]

        is_subscribed = False
        is_me = False
        if uid is not None:
            is_me = str(uid) == str(user_id)
            cur.execute(
                "SELECT 1 FROM subscriptions WHERE subscriber_id = %s AND subscribed_to_id = %s",
                (uid, user_id),
            )
            is_subscribed = cur.fetchone() is not None

    return {
        "id": str(user[0]), "nom": user[1], "prenom": user[2], "classe": user[3],
        "avatar_url": user[4], "relationship_status": user[5], "neighborhood": user[6],
        "favorite_subjects": user[7], "favorite_teacher": user[8], "interests": user[9],
        "followers": followers, "following": following, "posts_count": posts_count,
        "likes_received": likes_received, "comments_received": comments_received,
        "saves_received": saves_received,
        "is_subscribed": is_subscribed, "is_me": is_me,
    }

# -------------------------- POSTS + NOTIFICATIONS --------------------------

# AJOUT DE LA ROUTE DE CRÉATION DE POST (CORRIGE LE 405)
@app.post("/api/posts", status_code=201)
def create_post(data: CreatePostRequest, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO posts (user_id, media_url, media_type, title, description) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING id, created_at",
            (current_user["user_id"], data.media_url, data.media_type, data.title, data.description),
        )
        row = cur.fetchone()
    return {"status": "ok", "post_id": str(row[0]), "created_at": row[1]}

@app.get("/api/posts")
def list_posts(
    limit: int = Query(default=30, ge=1, le=100),
    user_id: Optional[str] = Query(default=None),
    media_type: Optional[str] = Query(default=None),
    saved_by: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
    current_user: Optional[dict] = Depends(get_optional_user),
):
    uid = current_user["user_id"] if current_user else None

    where = []
    where_params = []
    if user_id:
        where.append("p.user_id = %s")
        where_params.append(user_id)
    if media_type in ("image", "video"):
        where.append("p.media_type = %s")
        where_params.append(media_type)
    if saved_by:
        where.append("p.id IN (SELECT post_id FROM post_saves WHERE user_id = %s)")
        where_params.append(saved_by)
    if q:
        where.append("(p.title ILIKE %s OR p.description ILIKE %s)")
        where_params.extend([f"%{q}%", f"%{q}%"])

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT p.id, p.user_id, u.prenom, u.nom, u.avatar_url, p.media_url, p.media_type,
                   p.title, p.description, p.created_at,
                   (SELECT COUNT(*) FROM post_likes WHERE post_id = p.id) AS likes,
                   (SELECT COUNT(*) FROM post_saves WHERE post_id = p.id) AS saves,
                   (SELECT COUNT(*) FROM comments   WHERE post_id = p.id) AS comments,
                   EXISTS(SELECT 1 FROM post_likes    WHERE post_id = p.id AND user_id = %s) AS is_liked,
                   EXISTS(SELECT 1 FROM post_saves    WHERE post_id = p.id AND user_id = %s) AS is_saved,
                   EXISTS(SELECT 1 FROM subscriptions WHERE subscriber_id = %s AND subscribed_to_id = p.user_id) AS is_subscribed
            FROM posts p JOIN users u ON u.id = p.user_id
            {where_sql}
            ORDER BY p.created_at DESC LIMIT %s
            """,
            (uid, uid, uid, *where_params, limit),
        )
        rows = cur.fetchall()
    return [{
        "id": str(r[0]), "user_id": str(r[1]),
        "author_name": f"{r[2] or ''} {r[3] or ''}".strip(),
        "avatar_url": r[4], "media_url": r[5], "media_type": r[6],
        "title": r[7], "description": r[8], "created_at": r[9],
        "likes": r[10], "saves": r[11], "comments": r[12],
        "is_liked": bool(r[13]), "is_saved": bool(r[14]), "is_subscribed": bool(r[15]),
    } for r in rows]

@app.post("/api/posts/{post_id}/like")
def like_post(post_id: str, current_user: dict = Depends(get_current_user)):
    uid = current_user["user_id"]
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT user_id FROM posts WHERE id = %s", (post_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Publication introuvable.")
        owner_id = row[0]
        cur.execute(
            "INSERT INTO post_likes (post_id, user_id) VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING post_id",
            (post_id, uid),
        )
        if cur.fetchone():
            _create_notification(cur, owner_id, uid, "like", post_id)
    return {"status": "ok"}

@app.delete("/api/posts/{post_id}/like")
def unlike_post(post_id: str, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM post_likes WHERE post_id = %s AND user_id = %s", (post_id, current_user["user_id"]))
    return {"status": "ok"}

@app.post("/api/posts/{post_id}/save")
def save_post(post_id: str, current_user: dict = Depends(get_current_user)):
    uid = current_user["user_id"]
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT user_id FROM posts WHERE id = %s", (post_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Publication introuvable.")
        owner_id = row[0]
        cur.execute(
            "INSERT INTO post_saves (post_id, user_id) VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING post_id",
            (post_id, uid),
        )
        if cur.fetchone():
            _create_notification(cur, owner_id, uid, "save", post_id)
    return {"status": "ok"}

@app.delete("/api/posts/{post_id}/save")
def unsave_post(post_id: str, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM post_saves WHERE post_id = %s AND user_id = %s", (post_id, current_user["user_id"]))
    return {"status": "ok"}

@app.post("/api/posts/{post_id}/comment", status_code=201)
def comment_post(post_id: str, data: CommentRequest, current_user: dict = Depends(get_current_user)):
    uid = current_user["user_id"]
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT user_id FROM posts WHERE id = %s", (post_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Publication introuvable.")
        owner_id = row[0]
        cur.execute(
            "INSERT INTO comments (post_id, user_id, content) VALUES (%s, %s, %s) RETURNING id",
            (post_id, uid, data.content.strip()),
        )
        cid = cur.fetchone()[0]
        _create_notification(cur, owner_id, uid, "comment", post_id)
    return {"status": "ok", "comment_id": str(cid)}

@app.get("/api/posts/{post_id}/comments")
def list_comments(post_id: str):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT c.id, c.user_id, u.prenom, u.nom, u.avatar_url, c.content, c.created_at
            FROM comments c JOIN users u ON u.id = c.user_id
            WHERE c.post_id = %s ORDER BY c.created_at ASC LIMIT 200
            """,
            (post_id,),
        )
        rows = cur.fetchall()
    return [{
        "id": str(r[0]), "user_id": str(r[1]),
        "author_name": f"{r[2] or ''} {r[3] or ''}".strip(),
        "avatar_url": r[4], "content": r[5], "created_at": r[6],
    } for r in rows]

@app.post("/api/users/{user_id}/subscribe")
def subscribe_user(user_id: str, current_user: dict = Depends(get_current_user)):
    uid = current_user["user_id"]
    if str(uid) == str(user_id):
        raise HTTPException(status_code=400, detail="Impossible de s'abonner à soi-même.")
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
        cur.execute(
            "INSERT INTO subscriptions (subscriber_id, subscribed_to_id) VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING subscriber_id",
            (uid, user_id),
        )
        if cur.fetchone():
            _create_notification(cur, user_id, uid, "subscribe", None)
    return {"status": "ok"}

@app.delete("/api/users/{user_id}/subscribe")
def unsubscribe_user(user_id: str, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM subscriptions WHERE subscriber_id = %s AND subscribed_to_id = %s", (current_user["user_id"], user_id))
    return {"status": "ok"}

# -------------------------- LECTURE DES NOTIFICATIONS --------------------------

@app.get("/api/notifications")
def get_notifications(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT n.id, n.sender_id, u.prenom, u.nom, n.created_at, n.type, n.post_id
            FROM notifications n
            JOIN users u ON u.id = n.sender_id
            WHERE n.recipient_id = %s AND n.is_read = FALSE
            ORDER BY n.created_at DESC
            """,
            (current_user["user_id"],),
        )
        rows = cur.fetchall()
    return [{
        "id": str(r[0]), "sender_id": str(r[1]),
        "sender_name": " ".join(x for x in [r[2], r[3]] if x),
        "created_at": r[4], "type": r[5],
        "post_id": str(r[6]) if r[6] is not None else None,
    } for r in rows]

@app.post("/api/notifications/read")
def mark_notifications_read(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE notifications SET is_read = TRUE WHERE recipient_id = %s AND is_read = FALSE", (current_user["user_id"],))
    return {"status": "ok"}

# ============================================================
# BACK-OFFICE ADMINISTRATEUR
# ============================================================

@app.post("/api/admin/login")
def admin_login(data: AdminLoginRequest):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=503, detail="Configurer ADMIN_PASSWORD.")
    if not hmac.compare_digest(data.password, ADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="Mot de passe incorrect.")
    return {"status": "ok", "message": "Connexion réussie."}

@app.get("/api/admin/stats")
def admin_stats(_: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM users")
        users_total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users WHERE last_seen >= NOW() - INTERVAL '5 minutes'")
        users_online = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users WHERE last_seen >= date_trunc('day', NOW())")
        users_today = cur.fetchone()[0]
    return {"users_total": users_total, "users_online": users_online, "users_today": users_today}

@app.get("/api/admin/users")
def admin_list_users(_: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, nom, prenom, classe, email, created_at FROM users ORDER BY created_at DESC NULLS LAST, id DESC")
        rows = cur.fetchall()
    return [{"id": str(r[0]), "nom": r[1], "prenom": r[2], "classe": r[3], "email": r[4], "created_at": r[5], "is_online": False} for r in rows]

@app.get("/api/admin/tickets")
def admin_list_tickets(_: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT code, is_used, created_at FROM tickets ORDER BY created_at DESC NULLS LAST, code")
        rows = cur.fetchall()
    return [{"id": str(r[0]), "code": r[0], "is_used": bool(r[1]), "created_at": r[2]} for r in rows]

@app.post("/api/admin/tickets", status_code=201)
def admin_generate_tickets(data: AdminGenerateTicketsRequest, _: bool = Depends(require_admin)):
    generated = []
    with get_connection() as conn, conn.cursor() as cur:
        for _i in range(data.count):
            for _attempt in range(10):
                code = "DJN-" + secrets.token_hex(4).upper()
                cur.execute(
                    "INSERT INTO tickets (code, is_used, created_at) VALUES (%s, FALSE, NOW()) ON CONFLICT (code) DO NOTHING RETURNING code, is_used, created_at",
                    (code,),
                )
                row = cur.fetchone()
                if row:
                    generated.append({"id": row[0], "code": row[0], "is_used": bool(row[1]), "created_at": row[2]})
                    break
    return {"status": "ok", "count": len(generated), "tickets": generated}

@app.delete("/api/admin/tickets/{ticket_id}")
def admin_delete_ticket(ticket_id: str, _: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM tickets WHERE code = %s RETURNING code", (ticket_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Ticket introuvable.")
    return {"status": "ok"}

@app.post("/api/admin/users", status_code=201)
def admin_create_user(data: AdminCreateUserRequest, _: bool = Depends(require_admin)):
    email = str(data.email).strip().lower()
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Email déjà utilisé.")
        cur.execute(
            "INSERT INTO users (nom, prenom, classe, email, password, ticket_code) VALUES (%s, %s, %s, %s, %s, NULL) RETURNING id",
            (data.nom.strip(), data.prenom.strip(), data.classe.strip(), email, hash_password(data.password)),
        )
        row = cur.fetchone()
    return {"status": "ok", "user": {"id": str(row[0]), "nom": data.nom, "prenom": data.prenom, "classe": data.classe, "email": email}}

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: str, _: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM notifications WHERE recipient_id = %s OR sender_id = %s", (user_id, user_id))
        cur.execute("DELETE FROM subscriptions WHERE subscriber_id = %s OR subscribed_to_id = %s", (user_id, user_id))
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    return {"status": "ok"}

@app.put("/api/admin/tickets/{ticket_id}")
def admin_toggle_ticket(ticket_id: str, _: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE tickets SET is_used = NOT is_used WHERE code = %s RETURNING is_used", (ticket_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Ticket introuvable.")
    return {"status": "ok", "is_used": row[0]}