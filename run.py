"""Backend FastAPI de DjessouNet : authentification, posts, likes, pokes, notifications, avis et admin."""

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
from pydantic import BaseModel, EmailStr, Field

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

# --- FONCTION KEEP-ALIVE ---
# Ceci ping le serveur toutes les 2 minutes pour l'empêcher de s'endormir
async def keep_awake():
    url = "https://djessounet.onrender.com/api/status"
    while True:
        await asyncio.sleep(120) # Attend 2 minutes
        try:
            urllib.request.urlopen(url, timeout=10)
        except Exception:
            pass # Si ça échoue (ex: coupure), on ignore pour ne pas crasher

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Démarre la tâche en arrière-plan au lancement du serveur
    task = asyncio.create_task(keep_awake())
    yield
    # Arrête la tâche à la fermeture
    task.cancel()

app = FastAPI(title="DjessouNet API", version="3.1", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Autorise toutes les origines (y compris Live Server)
    allow_credentials=False, # Doit être False si allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    print(f"Erreur serveur sur {request.method} {request.url.path}: {exc!r}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Le serveur est momentanément indisponible. Réessaie dans quelques instants."},
    )

required_bearer = HTTPBearer()
optional_bearer = HTTPBearer(auto_error=False)

def get_connection():
    return psycopg.connect(DATABASE_URL, connect_timeout=15)

# -------------------------- Mot de passe et JWT --------------------------

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
        raise HTTPException(status_code=401, detail="Session expirée. Connecte-toi à nouveau.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide. Connecte-toi à nouveau.")

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

# -------------------------- Modèles JSON --------------------------

class RegisterRequest(BaseModel):
    nom: str = Field(min_length=1, max_length=100)
    prenom: str = Field(min_length=1, max_length=100)
    classe: str = Field(min_length=1, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    ticket: str = Field(min_length=1, max_length=100)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class PostRequest(BaseModel):
    content: str = Field(default="", max_length=1000)
    image_url: Optional[str] = Field(default=None, max_length=1_250_000)

class FeedbackRequest(BaseModel):
    type: str = Field(min_length=1, max_length=40)
    message: str = Field(min_length=1, max_length=2000)

class ReportRequest(BaseModel):
    reason: str = Field(default="À examiner par la modération", min_length=1, max_length=500)

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

class CommentRequest(BaseModel):
    content: str = Field(min_length=1, max_length=2000)

# -------------------------- Modèles Admin --------------------------

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

class AdminEditPostRequest(BaseModel):
    content: str = Field(max_length=1000)

def require_admin(x_admin_password: Optional[str] = Header(default=None, alias="X-Admin-Password")):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=503, detail="ADMIN_PASSWORD n'est pas configuré.")
    if not x_admin_password or not hmac.compare_digest(x_admin_password, ADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="Mot de passe administrateur invalide.")
    return True

# -------------------------- État général --------------------------

@app.api_route("/api/status", methods=["GET", "HEAD"])
def api_status():
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
        return {"status": "ok", "database": "connected"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Impossible de joindre la base de données.")

# -------------------------- Auth --------------------------

@app.post("/api/register", status_code=201)
def register(data: RegisterRequest):
    email = str(data.email).strip().lower()
    ticket = data.ticket.strip()
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT is_used FROM tickets WHERE code = %s FOR UPDATE", (ticket,))
            ticket_row = cur.fetchone()
            if not ticket_row or ticket_row[0]:
                raise HTTPException(status_code=400, detail="Ticket invalide ou déjà utilisé.")

            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Cette adresse e-mail est déjà utilisée.")

            cur.execute(
                "INSERT INTO users (nom, prenom, classe, email, password, ticket_code) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (data.nom.strip(), data.prenom.strip(), data.classe.strip(), email, hash_password(data.password), ticket),
            )
            user_id = cur.fetchone()[0]
            cur.execute("UPDATE tickets SET is_used = TRUE WHERE code = %s", (ticket,))
        return {"status": "ok", "message": "Inscription réussie.", "user_id": str(user_id)}
    except HTTPException:
        raise
    except Exception as exc:
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
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Impossible de se connecter.")

    if not user or not verify_password(data.password, user[4]):
        raise HTTPException(status_code=401, detail="E-mail ou mot de passe incorrect.")
    return {
        "status": "ok",
        "token": create_access_token(user[0]),
        "user": {"id": str(user[0]), "nom": user[1], "prenom": user[2], "classe": user[3], "avatar_url": user[5]},
    }

# -------------------------- Profil --------------------------

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
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Impossible de mettre à jour le profil.")

@app.get("/api/users")
def get_users(classe: Optional[str] = Query(default=None, max_length=50)):
    with get_connection() as conn, conn.cursor() as cur:
        if classe:
            cur.execute("SELECT id, nom, prenom, classe, avatar_url FROM users WHERE classe = %s ORDER BY prenom, nom LIMIT 100", (classe,))
        else:
            cur.execute("SELECT id, nom, prenom, classe, avatar_url FROM users ORDER BY prenom, nom LIMIT 100")
        rows = cur.fetchall()
    return [{"id": str(r[0]), "nom": r[1], "prenom": r[2], "classe": r[3], "avatar_url": r[4]} for r in rows]

@app.get("/api/users/search")
def search_users(q: str = Query(default="", max_length=100)):
    query = q.strip()
    if len(query) < 2: return []
    pattern = f"%{query}%"
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, nom, prenom, classe, avatar_url FROM users WHERE nom ILIKE %s OR prenom ILIKE %s OR classe ILIKE %s OR CONCAT(prenom, ' ', nom) ILIKE %s ORDER BY prenom, nom LIMIT 30", (pattern, pattern, pattern, pattern))
        rows = cur.fetchall()
    return [{"id": str(r[0]), "nom": r[1], "prenom": r[2], "classe": r[3], "avatar_url": r[4]} for r in rows]

@app.get("/api/users/{user_id}")
def get_user_profile(user_id: str):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, nom, prenom, classe, avatar_url, relationship_status, neighborhood, favorite_subjects, favorite_teacher, interests FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="Profil introuvable.")
    return {"id": str(user[0]), "nom": user[1], "prenom": user[2], "classe": user[3], "avatar_url": user[4], "relationship_status": user[5], "neighborhood": user[6], "favorite_subjects": user[7], "favorite_teacher": user[8], "interests": user[9]}

@app.get("/api/users/{user_id}/likes/count")
def get_user_received_likes_count(user_id: str):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM post_likes pl JOIN posts p ON p.id = pl.post_id WHERE p.author_id = %s", (user_id,))
        count = cur.fetchone()[0]
    return {"user_id": user_id, "count": count}

# -------------------------- Publications --------------------------

@app.post("/api/posts", status_code=201)
def create_post(data: PostRequest, current_user: dict = Depends(get_current_user)):
    content = data.content.strip()
    image_url = data.image_url
    if not content and not image_url:
        raise HTTPException(status_code=400, detail="Ajoute un texte ou une image.")
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO posts (author_id, content, image_url, likes, created_at) VALUES (%s, %s, %s, 0, NOW()) RETURNING id, content, image_url, created_at, author_id", (current_user["user_id"], content, image_url))
        row = cur.fetchone()
    return {"status": "ok", "post": {"id": str(row[0]), "content": row[1], "image_url": row[2], "created_at": row[3], "likes": 0, "author_id": str(row[4])}}


@app.get("/api/posts")
def get_posts(current_user: Optional[dict] = Depends(get_optional_user)):
    user_id = current_user["user_id"] if current_user else None
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT p.id, p.content, p.image_url, p.created_at, COALESCE(l.like_count, 0) AS likes, p.author_id,
                   TRIM(CONCAT(u.prenom, ' ', u.nom)) AS author_name, u.classe AS author_class,
                   u.relationship_status AS author_relationship_status, u.avatar_url AS author_avatar_url,
                   COALESCE((
                       SELECT json_agg(json_build_object(
                           'id', c.id, 'content', c.content, 'created_at', c.created_at, 
                           'user_id', c.user_id, 'author_name', TRIM(CONCAT(cu.prenom, ' ', cu.nom)), 
                           'avatar_url', cu.avatar_url, 'author_class', cu.classe, 
                           'author_relationship_status', cu.relationship_status
                       ) ORDER BY c.created_at ASC) 
                       FROM comments c JOIN users cu ON cu.id = c.user_id WHERE c.post_id = p.id
                   ), '[]'::json) AS comments,
                   EXISTS (SELECT 1 FROM post_likes mine WHERE mine.post_id = p.id AND mine.user_id = %s) AS liked_by_me,
                   EXISTS (SELECT 1 FROM reports r WHERE r.post_id = p.id AND r.reporter_id = %s) AS reported_by_me
            FROM posts p JOIN users u ON u.id = p.author_id
            LEFT JOIN (SELECT post_id, COUNT(*) AS like_count FROM post_likes GROUP BY post_id) l ON l.post_id = p.id
            ORDER BY p.created_at DESC
        """, (user_id, user_id))
        rows = cur.fetchall()
    return [{
        "id": str(r[0]), "content": r[1] or "", "image_url": r[2], "created_at": r[3], "likes": r[4], "author_id": str(r[5]),
        "author_name": r[6] or "Élève", "author_class": r[7] or "", "author_relationship_status": r[8] or "", "author_avatar_url": r[9], "comments": r[10] or [],
        "liked_by_me": bool(r[11]), "reported_by_me": bool(r[12]),
    } for r in rows]


@app.post("/api/posts/{post_id}/comment", status_code=201)
def create_comment(post_id: str, data: CommentRequest, current_user: dict = Depends(get_current_user)):
    content = data.content.strip()
    if not content: raise HTTPException(status_code=400, detail="Commentaire vide.")
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT author_id FROM posts WHERE id = %s", (post_id,))
        post = cur.fetchone()
        if not post: raise HTTPException(status_code=404, detail="Publication introuvable.")
        cur.execute("INSERT INTO comments (post_id, user_id, content, created_at) VALUES (%s, %s, %s, NOW()) RETURNING id, created_at", (post_id, current_user["user_id"], content))
        comment = cur.fetchone()
        if str(post[0]) != str(current_user["user_id"]):
            cur.execute("INSERT INTO notifications (recipient_id, sender_id, type, post_id, is_read, created_at) VALUES (%s, %s, 'comment', %s, FALSE, NOW())", (post[0], current_user["user_id"], post_id))
        cur.execute("SELECT nom, prenom, avatar_url FROM users WHERE id = %s", (current_user["user_id"],))
        author = cur.fetchone()
    return {"status": "ok", "comment": {"id": str(comment[0]), "post_id": str(post_id), "user_id": str(current_user["user_id"]), "content": content, "created_at": comment[1], "author_name": " ".join(x for x in [author[1], author[0]] if x), "avatar_url": author[2]}}

@app.post("/api/posts/{post_id}/like")
def like_post(post_id: str, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT author_id FROM posts WHERE id = %s", (post_id,))
        owner = cur.fetchone()
        if not owner: raise HTTPException(status_code=404, detail="Publication introuvable.")
        cur.execute("INSERT INTO post_likes (post_id, user_id) VALUES (%s, %s) ON CONFLICT DO NOTHING", (post_id, current_user["user_id"]))
        if cur.rowcount and str(owner[0]) != str(current_user["user_id"]):
            cur.execute("INSERT INTO notifications (recipient_id, sender_id, type, post_id, is_read, created_at) VALUES (%s, %s, 'like', %s, FALSE, NOW())", (owner[0], current_user["user_id"], post_id))
        cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s", (post_id,))
        count = cur.fetchone()[0]
    return {"status": "ok", "liked": True, "likes": count}

@app.delete("/api/posts/{post_id}/like")
def unlike_post(post_id: str, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM post_likes WHERE post_id = %s AND user_id = %s", (post_id, current_user["user_id"]))
        cur.execute("SELECT COUNT(*) FROM post_likes WHERE post_id = %s", (post_id,))
        count = cur.fetchone()[0]
    return {"status": "ok", "liked": False, "likes": count}

@app.post("/api/posts/{post_id}/report", status_code=201)
def report_post(post_id: str, data: ReportRequest, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO reports (post_id, reporter_id, reason, status, created_at) VALUES (%s, %s, %s, 'pending', NOW()) ON CONFLICT DO NOTHING", (post_id, current_user["user_id"], data.reason.strip()))
    return {"status": "ok", "message": "Signalement enregistré."}

# -------------------------- Pokes & Notifications --------------------------

@app.post("/api/poke/{receiver_id}", status_code=201)
def create_poke(receiver_id: str, current_user: dict = Depends(get_current_user)):
    sender_id = current_user["user_id"]
    if str(sender_id) == str(receiver_id): raise HTTPException(status_code=400, detail="Impossible de se poke soi-même.")
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM pokes WHERE sender_id = %s AND receiver_id = %s AND created_at >= date_trunc('day', NOW())", (sender_id, receiver_id))
        if cur.fetchone()[0] >= 2: raise HTTPException(status_code=429, detail="Limite de 2 pokes par jour atteinte.")
        cur.execute("INSERT INTO pokes (sender_id, receiver_id, created_at, is_read) VALUES (%s, %s, NOW(), FALSE)", (sender_id, receiver_id))
        cur.execute("INSERT INTO notifications (recipient_id, sender_id, type, is_read, created_at) VALUES (%s, %s, 'poke', FALSE, NOW())", (receiver_id, sender_id))
    return {"status": "ok", "message": "Poke envoyé."}

@app.get("/api/pokes/count/{user_id}")
def get_pokes_count(user_id: str):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM pokes WHERE receiver_id = %s", (user_id,))
        count = cur.fetchone()[0]
    return {"user_id": user_id, "count": count}

@app.get("/api/notifications")
def get_notifications(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        # On ne lit QUE dans la table notifications maintenant (fini les doublons)
        cur.execute("""
            SELECT n.id, n.sender_id, u.prenom, u.nom, n.created_at, n.type, n.post_id 
            FROM notifications n 
            JOIN users u ON u.id = n.sender_id 
            WHERE n.recipient_id = %s AND n.is_read = FALSE 
            ORDER BY n.created_at DESC
        """, (current_user["user_id"],))
        rows = cur.fetchall()
    
    result = [{
        "id": str(r[0]), 
        "sender_id": str(r[1]), 
        "sender_name": " ".join(x for x in [r[2], r[3]] if x), 
        "created_at": r[4], 
        "type": r[5], 
        "post_id": str(r[6]) if r[6] is not None else None
    } for r in rows]
    
    return result

@app.post("/api/notifications/read")
def mark_notifications_read(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE pokes SET is_read = TRUE WHERE receiver_id = %s AND is_read = FALSE", (current_user["user_id"],))
        cur.execute("UPDATE notifications SET is_read = TRUE WHERE recipient_id = %s AND is_read = FALSE", (current_user["user_id"],))
    return {"status": "ok"}

# -------------------------- Avis --------------------------

@app.post("/api/feedback", status_code=201)
def create_feedback(data: FeedbackRequest, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO feedbacks (user_id, type, message, status, created_at) VALUES (%s, %s, %s, 'new', NOW()) RETURNING id", (current_user["user_id"], data.type, data.message.strip()))
    return {"status": "ok"}

# --- NOUVELLE ROUTE AJOUTÉE ICI POUR LE MUR DES AVIS ---
@app.get("/api/feedback")
def get_feedback_wall():
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT f.id, f.type, f.message, f.created_at, u.id, u.nom, u.prenom, u.classe
                FROM feedbacks f
                JOIN users u ON u.id = f.user_id
                ORDER BY f.created_at DESC
            """)
            rows = cur.fetchall()
        return [
            {
                "id": str(r[0]), "type": r[1], "message": r[2], "created_at": r[3],
                "user_id": str(r[4]), "nom": r[5], "prenom": r[6], "classe": r[7]
            }
            for r in rows
        ]
    except Exception as exc:
        print("GET /api/feedback:", repr(exc))
        raise HTTPException(status_code=503, detail="Impossible de charger les avis.")


# ============================================================
# BACK-OFFICE ADMINISTRATEUR
# ============================================================

@app.post("/api/admin/login")
def admin_login(data: AdminLoginRequest):
    if not ADMIN_PASSWORD: raise HTTPException(status_code=503, detail="Configurer ADMIN_PASSWORD.")
    if not hmac.compare_digest(data.password, ADMIN_PASSWORD): raise HTTPException(status_code=401, detail="Mot de passe incorrect.")
    return {"status": "ok", "message": "Connexion réussie."}

@app.get("/api/admin/stats")
def admin_stats(_: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM users")
        users_total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users WHERE last_seen >= NOW() - INTERVAL '5 minutes'")
        users_online = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM posts")
        posts_total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM reports WHERE COALESCE(status, 'pending') IN ('pending', 'new')")
        pending_reports = cur.fetchone()[0]
    return {"users_total": users_total, "users_online": users_online, "posts_total": posts_total, "pending_reports": pending_reports}

@app.get("/api/admin/users")
def admin_list_users(_: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, nom, prenom, classe, email, created_at FROM users ORDER BY created_at DESC NULLS LAST, id DESC")
        rows = cur.fetchall()
    return [{"id": str(r[0]), "nom": r[1], "prenom": r[2], "classe": r[3], "email": r[4], "created_at": r[5], "is_online": False} for r in rows]

@app.get("/api/admin/posts")
def admin_list_posts(_: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT p.id, p.content, p.image_url, p.created_at, TRIM(CONCAT(u.prenom, ' ', u.nom)), u.classe FROM posts p LEFT JOIN users u ON u.id = p.author_id ORDER BY p.created_at DESC")
        rows = cur.fetchall()
    return [{"id": str(r[0]), "content": r[1] or "", "image_url": r[2], "created_at": r[3], "author_name": r[4] or "Inconnu", "author_class": r[5] or ""} for r in rows]

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
                cur.execute("INSERT INTO tickets (code, is_used, created_at) VALUES (%s, FALSE, NOW()) ON CONFLICT (code) DO NOTHING RETURNING code, is_used, created_at", (code,))
                row = cur.fetchone()
                if row:
                    generated.append({"id": row[0], "code": row[0], "is_used": bool(row[1]), "created_at": row[2]})
                    break
    return {"status": "ok", "count": len(generated), "tickets": generated}

@app.delete("/api/admin/tickets/{ticket_id}")
def admin_delete_ticket(ticket_id: str, _: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM tickets WHERE code = %s RETURNING code", (ticket_id,))
        if not cur.fetchone(): raise HTTPException(status_code=404, detail="Ticket introuvable.")
    return {"status": "ok"}

@app.post("/api/admin/users", status_code=201)
def admin_create_user(data: AdminCreateUserRequest, _: bool = Depends(require_admin)):
    email = str(data.email).strip().lower()
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone(): raise HTTPException(status_code=409, detail="Email déjà utilisé.")
        cur.execute("INSERT INTO users (nom, prenom, classe, email, password, ticket_code) VALUES (%s, %s, %s, %s, %s, NULL) RETURNING id", (data.nom.strip(), data.prenom.strip(), data.classe.strip(), email, hash_password(data.password)))
        row = cur.fetchone()
    return {"status": "ok", "user": {"id": str(row[0]), "nom": data.nom, "prenom": data.prenom, "classe": data.classe, "email": email}}

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: str, _: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM post_likes WHERE user_id = %s OR post_id IN (SELECT id FROM posts WHERE author_id = %s)", (user_id, user_id))
        cur.execute("DELETE FROM reports WHERE reporter_id = %s OR post_id IN (SELECT id FROM posts WHERE author_id = %s)", (user_id, user_id))
        cur.execute("DELETE FROM pokes WHERE sender_id = %s OR receiver_id = %s", (user_id, user_id))
        cur.execute("DELETE FROM feedbacks WHERE user_id = %s", (user_id,))
        cur.execute("DELETE FROM posts WHERE author_id = %s", (user_id,))
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    return {"status": "ok"}

@app.put("/api/admin/posts/{post_id}")
def admin_edit_post(post_id: str, data: AdminEditPostRequest, _: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE posts SET content = %s WHERE id = %s RETURNING id", (data.content.strip(), post_id))
        if not cur.fetchone(): raise HTTPException(status_code=404, detail="Publication introuvable.")
    return {"status": "ok"}

@app.delete("/api/admin/posts/{post_id}")
def admin_delete_post(post_id: str, _: bool = Depends(require_admin)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM post_likes WHERE post_id = %s", (post_id,))
        cur.execute("DELETE FROM reports WHERE post_id = %s", (post_id,))
        cur.execute("DELETE FROM posts WHERE id = %s", (post_id,))
    return {"status": "ok"}