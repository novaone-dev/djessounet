"""Backend FastAPI de DjessouNet."""

import os
import hmac
import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt
import psycopg
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_DAYS = 7

app = FastAPI(title="DjessouNet API", version="2.2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # On autorise tout pour le test
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

required_bearer = HTTPBearer()
optional_bearer = HTTPBearer(auto_error=False)

def get_connection():
    return psycopg.connect(DATABASE_URL, connect_timeout=15)

def hash_password(password: str) -> str:
    iterations = 600_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode('ascii')}${base64.b64encode(digest).decode('ascii')}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256": return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except: return False

def create_access_token(user_id) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(user_id), "iat": now, "exp": now + timedelta(days=JWT_DAYS)}, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if not payload.get("sub"): raise HTTPException(status_code=401, detail="Token invalide.")
        return payload
    except:
        raise HTTPException(status_code=401, detail="Session invalide ou expirée.")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(required_bearer)):
    payload = decode_token(credentials.credentials)
    return {"user_id": payload["sub"]}

def get_optional_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_bearer)):
    if not credentials: return None
    try: return {"user_id": decode_token(credentials.credentials)["sub"]}
    except: return None

# -------------------------- Modèles --------------------------
class RegisterRequest(BaseModel):
    nom: str; prenom: str; classe: str; email: EmailStr; password: str; ticket: str

class LoginRequest(BaseModel):
    email: EmailStr; password: str

class ProfileUpdate(BaseModel):
    neighborhood: Optional[str] = None; relationship_status: Optional[str] = None
    favorite_subjects: Optional[str] = None; favorite_teacher: Optional[str] = None
    interests: Optional[str] = None

class PostRequest(BaseModel):
    content: str = ""; image_url: Optional[str] = None

class FeedbackRequest(BaseModel):
    type: str; message: str

class ReportRequest(BaseModel):
    reason: str

# -------------------------- Routes --------------------------

@app.get("/api/status")
def api_status():
    try:
        with get_connection() as conn, conn.cursor() as cur: cur.execute("SELECT 1")
        return {"status": "ok", "database": "connected"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Base de données indisponible.")

@app.post("/api/register", status_code=201)
def register(data: RegisterRequest):
    email = str(data.email).strip().lower()
    ticket = data.ticket.strip()
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT is_used FROM tickets WHERE code = %s FOR UPDATE", (ticket,))
            if not cur.fetchone()[0]:
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cur.fetchone(): raise HTTPException(status_code=409, detail="Email déjà utilisé.")
                cur.execute("""INSERT INTO users (nom, prenom, classe, email, password, ticket_code) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""", (data.nom.strip(), data.prenom.strip(), data.classe.strip(), email, hash_password(data.password), ticket))
                user_id = cur.fetchone()[0]
                cur.execute("UPDATE tickets SET is_used = TRUE WHERE code = %s", (ticket,))
                return {"status": "ok", "user_id": str(user_id)}
            else: raise HTTPException(status_code=400, detail="Ticket déjà utilisé.")
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=503, detail="Erreur inscription.")

@app.post("/api/login")
def login(data: LoginRequest):
    email = str(data.email).strip().lower()
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, nom, prenom, classe, password FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
    if not user or not verify_password(data.password, user[4]):
        raise HTTPException(status_code=401, detail="E-mail ou mot de passe incorrect.")
    return {"status": "ok", "token": create_access_token(user[0]), "user": {"id": str(user[0]), "nom": user[1], "prenom": user[2], "classe": user[3]}}

@app.get("/api/me")
def me(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, nom, prenom, classe, email, neighborhood, relationship_status, favorite_subjects, favorite_teacher, interests FROM users WHERE id = %s", (current_user["user_id"],))
        u = cur.fetchone()
    if not u: raise HTTPException(status_code=401)
    return {"id": str(u[0]), "nom": u[1], "prenom": u[2], "classe": u[3], "email": u[4], "neighborhood": u[5], "relationship_status": u[6], "favorite_subjects": u[7], "favorite_teacher": u[8], "interests": u[9]}

@app.put("/api/users/me")
def update_my_profile(data: ProfileUpdate, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("""UPDATE users SET neighborhood=%s, relationship_status=%s, favorite_subjects=%s, favorite_teacher=%s, interests=%s WHERE id=%s RETURNING id""", (data.neighborhood, data.relationship_status, data.favorite_subjects, data.favorite_teacher, data.interests, current_user["user_id"]))
        return {"status": "ok", "message": "Profil mis à jour."}

@app.get("/api/users")
def get_users(classe: Optional[str] = Query(default=None)):
    with get_connection() as conn, conn.cursor() as cur:
        if classe:
            cur.execute("SELECT id, nom, prenom, classe FROM users WHERE classe = %s ORDER BY prenom, nom LIMIT 100", (classe,))
        else:
            cur.execute("SELECT id, nom, prenom, classe FROM users ORDER BY prenom, nom LIMIT 100")
        rows = cur.fetchall()
    return [{"id": str(r[0]), "nom": r[1], "prenom": r[2], "classe": r[3]} for r in rows]

@app.get("/api/users/{user_id}")
def get_user_profile(user_id: str):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, nom, prenom, classe, neighborhood, relationship_status, favorite_subjects, favorite_teacher, interests FROM users WHERE id = %s", (user_id,))
        u = cur.fetchone()
    if not u: raise HTTPException(status_code=404, detail="Profil introuvable.")
    return {"id": str(u[0]), "nom": u[1], "prenom": u[2], "classe": u[3], "neighborhood": u[4], "relationship_status": u[5], "favorite_subjects": u[6], "favorite_teacher": u[7], "interests": u[8]}

@app.get("/api/users/{user_id}/likes/count")
def get_user_received_likes_count(user_id: str):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM post_likes pl JOIN posts p ON p.id = pl.post_id WHERE p.author_id = %s", (user_id,))
        return {"user_id": user_id, "count": cur.fetchone()[0]}

@app.get("/api/posts")
def get_posts(current_user: Optional[dict] = Depends(get_optional_user)):
    user_id = current_user["user_id"] if current_user else None
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("""SELECT p.id, p.content, p.image_url, p.created_at, COALESCE(l.like_count, 0), p.author_id, TRIM(CONCAT(u.prenom, ' ', u.nom)), u.classe, EXISTS (SELECT 1 FROM post_likes mine WHERE mine.post_id = p.id AND mine.user_id = %s) FROM posts p JOIN users u ON u.id = p.author_id LEFT JOIN (SELECT post_id, COUNT(*) AS like_count FROM post_likes GROUP BY post_id) l ON l.post_id = p.id ORDER BY p.created_at DESC LIMIT 100""", (user_id,))
        rows = cur.fetchall()
    return [{"id": str(r[0]), "content": r[1] or "", "image_url": r[2], "created_at": r[3], "likes": r[4], "author_id": str(r[5]), "author_name": r[6] or "Élève", "author_class": r[7] or "", "liked_by_me": bool(r[8])} for r in rows]

@app.post("/api/posts", status_code=201)
def create_post(data: PostRequest, current_user: dict = Depends(get_current_user)):
    if not data.content.strip() and not data.image_url: raise HTTPException(status_code=400, detail="Vide.")
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO posts (author_id, content, image_url, likes, created_at) VALUES (%s, %s, %s, 0, NOW()) RETURNING id, content, image_url, created_at, author_id", (current_user["user_id"], data.content.strip(), data.image_url))
        row = cur.fetchone()
    return {"status": "ok", "post": {"id": str(row[0]), "content": row[1], "image_url": row[2], "created_at": row[3], "likes": 0, "author_id": str(row[4])}}

@app.post("/api/posts/{post_id}/like")
def like_post(post_id: str, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT author_id FROM posts WHERE id = %s", (post_id,))
        post = cur.fetchone()
        if not post: raise HTTPException(status_code=404)
        
        cur.execute("INSERT INTO post_likes (post_id, user_id) VALUES (%s, %s) ON CONFLICT DO NOTHING", (post_id, current_user["user_id"]))
        
        # Création de la notification de LIKE
        if str(post[0]) != str(current_user["user_id"]):
            cur.execute("""INSERT INTO notifications (receiver_id, sender_id, type, post_id, is_read, created_at) VALUES (%s, %s, 'like', %s, FALSE, NOW())""", (post[0], current_user["user_id"], post_id))
            
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
    return {"status": "ok", "message": "Signalé."}

@app.post("/api/poke/{receiver_id}", status_code=201)
def create_poke(receiver_id: str, current_user: dict = Depends(get_current_user)):
    sender_id = current_user["user_id"]
    if str(sender_id) == str(receiver_id): raise HTTPException(status_code=400, detail="Soi-même.")
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM pokes WHERE sender_id = %s AND receiver_id = %s AND created_at >= date_trunc('day', NOW())", (sender_id, receiver_id))
        if cur.fetchone()[0] >= 2: raise HTTPException(status_code=429, detail="Limite de 2 pokes.")
        
        cur.execute("INSERT INTO pokes (sender_id, receiver_id, created_at, is_read) VALUES (%s, %s, NOW(), FALSE)", (sender_id, receiver_id))
        
        # Création de la notification de POKE
        cur.execute("""INSERT INTO notifications (receiver_id, sender_id, type, is_read, created_at) VALUES (%s, %s, 'poke', FALSE, NOW())""", (receiver_id, sender_id))
    return {"status": "ok", "message": "Poke envoyé."}

@app.get("/api/pokes/count/{user_id}")
def get_pokes_count(user_id: str):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM pokes WHERE receiver_id = %s", (user_id,))
        return {"user_id": user_id, "count": cur.fetchone()[0]}

@app.get("/api/notifications")
def get_notifications(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("""SELECT n.id, n.type, n.post_id, n.created_at, u.prenom, u.nom 
                       FROM notifications n JOIN users u ON u.id = n.sender_id 
                       WHERE n.receiver_id = %s AND n.is_read = FALSE 
                       ORDER BY n.created_at DESC""", (current_user["user_id"],))
        rows = cur.fetchall()
    return [{"id": str(r[0]), "type": r[1], "post_id": str(r[2]) if r[2] else None, "created_at": r[3], "sender_name": f"{r[4]} {r[5]}"} for r in rows]

@app.post("/api/notifications/read")
def mark_notifications_read(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE notifications SET is_read = TRUE WHERE receiver_id = %s AND is_read = FALSE", (current_user["user_id"],))
        return {"status": "ok"}

@app.get("/api/feedback")
def get_feedback():
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("""SELECT f.id, f.type, f.message, f.created_at, u.id, u.nom, u.prenom, u.classe 
                       FROM feedbacks f JOIN users u ON u.id = f.user_id ORDER BY f.created_at DESC LIMIT 200""")
        rows = cur.fetchall()
    return [{"id": str(r[0]), "type": r[1], "message": r[2], "created_at": r[3], "user_id": str(r[4]), "nom": r[5], "prenom": r[6], "classe": r[7]} for r in rows]

@app.post("/api/feedback", status_code=201)
def create_feedback(data: FeedbackRequest, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO feedbacks (user_id, type, message, status, created_at) VALUES (%s, %s, %s, 'new', NOW()) RETURNING id", (current_user["user_id"], data.type, data.message.strip()))
        return {"status": "ok"}