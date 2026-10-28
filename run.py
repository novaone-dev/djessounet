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
from fastapi import FastAPI, Depends, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

JWT_ALGORITHM = "HS256"
JWT_DAYS = 7

app = FastAPI(title="DjessouNet API", version="2.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

required_bearer = HTTPBearer()
optional_bearer = HTTPBearer(auto_error=False)


# ------------------------------------------------------------
# Connexion à la base de données
# ------------------------------------------------------------

def get_connection():
    if not DATABASE_URL:
        raise HTTPException(
            status_code=503,
            detail="La variable DATABASE_URL est absente du fichier .env.",
        )

    return psycopg.connect(DATABASE_URL, connect_timeout=15)


# ------------------------------------------------------------
# Mots de passe et sessions des élèves
# ------------------------------------------------------------

def hash_password(password: str) -> str:
    iterations = 600_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    return (
        f"pbkdf2_sha256${iterations}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(digest).decode('ascii')}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored_hash.split("$")

        if algorithm != "pbkdf2_sha256":
            return False

        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations),
        )

        return hmac.compare_digest(actual, expected)

    except (ValueError, TypeError, base64.binascii.Error):
        return False


def create_access_token(user_id) -> str:
    if not JWT_SECRET:
        raise HTTPException(
            status_code=503,
            detail="La variable JWT_SECRET est absente du fichier .env.",
        )

    now = datetime.now(timezone.utc)

    return jwt.encode(
        {
            "sub": str(user_id),
            "iat": now,
            "exp": now + timedelta(days=JWT_DAYS),
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def decode_token(token: str) -> dict:
    try:
        if not JWT_SECRET:
            raise HTTPException(
                status_code=503,
                detail="Configuration de session absente.",
            )

        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )

        if not payload.get("sub"):
            raise HTTPException(
                status_code=401,
                detail="Token invalide.",
            )

        return payload

    except HTTPException:
        raise
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401,
            detail="Session invalide ou expirée.",
        )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(required_bearer),
):
    payload = decode_token(credentials.credentials)
    return {"user_id": payload["sub"]}


def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_bearer),
):
    if not credentials:
        return None

    try:
        return {
            "user_id": decode_token(credentials.credentials)["sub"]
        }
    except HTTPException:
        return None


# ------------------------------------------------------------
# Sécurité du back-office administrateur
# ------------------------------------------------------------

def verify_admin(
    admin_password: Optional[str] = Header(
        default=None,
        alias="X-Admin-Password",
    ),
):
    """
    Protège les routes d'administration.

    Le navigateur doit envoyer le mot de passe dans l'en-tête
    X-Admin-Password. La comparaison se fait côté serveur.
    """

    if not ADMIN_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail="Le mot de passe administrateur n'est pas configuré.",
        )

    if not admin_password or not hmac.compare_digest(
        admin_password,
        ADMIN_PASSWORD,
    ):
        raise HTTPException(
            status_code=401,
            detail="Accès administrateur refusé.",
        )

    return True


# ------------------------------------------------------------
# Modèles des requêtes
# ------------------------------------------------------------

class RegisterRequest(BaseModel):
    nom: str
    prenom: str
    classe: str
    email: EmailStr
    password: str
    ticket: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProfileUpdate(BaseModel):
    neighborhood: Optional[str] = None
    relationship_status: Optional[str] = None
    favorite_subjects: Optional[str] = None
    favorite_teacher: Optional[str] = None
    interests: Optional[str] = None


class PostRequest(BaseModel):
    content: str = ""
    image_url: Optional[str] = None


class FeedbackRequest(BaseModel):
    type: str
    message: str


class ReportRequest(BaseModel):
    reason: str


class AdminLoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


# ------------------------------------------------------------
# Route de vérification de l'API
# ------------------------------------------------------------

@app.get("/api/status")
def api_status():
    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")

        return {
            "status": "ok",
            "database": "connected",
        }

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Base de données indisponible.",
        )


# ------------------------------------------------------------
# Inscription des élèves
# ------------------------------------------------------------

@app.post("/api/register", status_code=201)
def register(data: RegisterRequest):
    email = str(data.email).strip().lower()
    ticket = data.ticket.strip()

    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT is_used FROM tickets WHERE code = %s FOR UPDATE",
                (ticket,),
            )
            ticket_row = cur.fetchone()

            if not ticket_row:
                raise HTTPException(
                    status_code=400,
                    detail="Ticket introuvable.",
                )

            if ticket_row[0]:
                raise HTTPException(
                    status_code=400,
                    detail="Ticket déjà utilisé.",
                )

            cur.execute(
                "SELECT id FROM users WHERE email = %s",
                (email,),
            )

            if cur.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="Email déjà utilisé.",
                )

            cur.execute(
                """
                INSERT INTO users
                    (nom, prenom, classe, email, password, ticket_code)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    data.nom.strip(),
                    data.prenom.strip(),
                    data.classe.strip(),
                    email,
                    hash_password(data.password),
                    ticket,
                ),
            )

            user_id = cur.fetchone()[0]

            cur.execute(
                "UPDATE tickets SET is_used = TRUE WHERE code = %s",
                (ticket,),
            )

        return {
            "status": "ok",
            "user_id": str(user_id),
        }

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Erreur lors de l'inscription.",
        )


# ------------------------------------------------------------
# Connexion des élèves
# Met à jour last_seen après authentification réussie.
# ------------------------------------------------------------

@app.post("/api/login")
def login(data: LoginRequest):
    email = str(data.email).strip().lower()

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, nom, prenom, classe, password
            FROM users
            WHERE email = %s
            """,
            (email,),
        )
        user = cur.fetchone()

        if not user or not verify_password(data.password, user[4]):
            raise HTTPException(
                status_code=401,
                detail="E-mail ou mot de passe incorrect.",
            )

        cur.execute(
            "UPDATE users SET last_seen = NOW() WHERE id = %s",
            (user[0],),
        )

    return {
        "status": "ok",
        "token": create_access_token(user[0]),
        "user": {
            "id": str(user[0]),
            "nom": user[1],
            "prenom": user[2],
            "classe": user[3],
        },
    }


# ------------------------------------------------------------
# Profil de l'élève connecté
# Met à jour last_seen à chaque appel.
# ------------------------------------------------------------

@app.get("/api/me")
def me(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET last_seen = NOW() WHERE id = %s",
            (current_user["user_id"],),
        )

        cur.execute(
            """
            SELECT
                id, nom, prenom, classe, email,
                neighborhood, relationship_status,
                favorite_subjects, favorite_teacher, interests
            FROM users
            WHERE id = %s
            """,
            (current_user["user_id"],),
        )
        u = cur.fetchone()

    if not u:
        raise HTTPException(
            status_code=401,
            detail="Compte introuvable.",
        )

    return {
        "id": str(u[0]),
        "nom": u[1],
        "prenom": u[2],
        "classe": u[3],
        "email": u[4],
        "neighborhood": u[5],
        "relationship_status": u[6],
        "favorite_subjects": u[7],
        "favorite_teacher": u[8],
        "interests": u[9],
    }


# ------------------------------------------------------------
# Modification du profil de l'élève
# ------------------------------------------------------------

@app.put("/api/users/me")
def update_my_profile(
    data: ProfileUpdate,
    current_user: dict = Depends(get_current_user),
):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET neighborhood = %s,
                relationship_status = %s,
                favorite_subjects = %s,
                favorite_teacher = %s,
                interests = %s
            WHERE id = %s
            RETURNING id
            """,
            (
                data.neighborhood,
                data.relationship_status,
                data.favorite_subjects,
                data.favorite_teacher,
                data.interests,
                current_user["user_id"],
            ),
        )

        if not cur.fetchone():
            raise HTTPException(
                status_code=404,
                detail="Compte introuvable.",
            )

    return {
        "status": "ok",
        "message": "Profil mis à jour.",
    }


# ------------------------------------------------------------
# Liste des élèves visible sur le site principal
# ------------------------------------------------------------

@app.get("/api/users")
def get_users(classe: Optional[str] = Query(default=None)):
    with get_connection() as conn, conn.cursor() as cur:
        if classe:
            cur.execute(
                """
                SELECT id, nom, prenom, classe
                FROM users
                WHERE classe = %s
                ORDER BY prenom, nom
                LIMIT 100
                """,
                (classe,),
            )
        else:
            cur.execute(
                """
                SELECT id, nom, prenom, classe
                FROM users
                ORDER BY prenom, nom
                LIMIT 100
                """
            )

        rows = cur.fetchall()

    return [
        {
            "id": str(r[0]),
            "nom": r[1],
            "prenom": r[2],
            "classe": r[3],
        }
        for r in rows
    ]


@app.get("/api/users/{user_id}")
def get_user_profile(user_id: str):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                id, nom, prenom, classe, neighborhood,
                relationship_status, favorite_subjects,
                favorite_teacher, interests
            FROM users
            WHERE id = %s
            """,
            (user_id,),
        )
        u = cur.fetchone()

    if not u:
        raise HTTPException(
            status_code=404,
            detail="Profil introuvable.",
        )

    return {
        "id": str(u[0]),
        "nom": u[1],
        "prenom": u[2],
        "classe": u[3],
        "neighborhood": u[4],
        "relationship_status": u[5],
        "favorite_subjects": u[6],
        "favorite_teacher": u[7],
        "interests": u[8],
    }


@app.get("/api/users/{user_id}/likes/count")
def get_user_received_likes_count(user_id: str):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM post_likes pl
            JOIN posts p ON p.id = pl.post_id
            WHERE p.author_id = %s
            """,
            (user_id,),
        )
        count = cur.fetchone()[0]

    return {
        "user_id": user_id,
        "count": count,
    }


# ------------------------------------------------------------
# Publications du site principal
# ------------------------------------------------------------

@app.get("/api/posts")
def get_posts(current_user: Optional[dict] = Depends(get_optional_user)):
    user_id = current_user["user_id"] if current_user else None

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                p.id,
                p.content,
                p.image_url,
                p.created_at,
                COALESCE(l.like_count, 0),
                p.author_id,
                TRIM(CONCAT(u.prenom, ' ', u.nom)),
                u.classe,
                EXISTS (
                    SELECT 1
                    FROM post_likes mine
                    WHERE mine.post_id = p.id
                      AND mine.user_id = %s
                )
            FROM posts p
            JOIN users u ON u.id = p.author_id
            LEFT JOIN (
                SELECT post_id, COUNT(*) AS like_count
                FROM post_likes
                GROUP BY post_id
            ) l ON l.post_id = p.id
            ORDER BY p.created_at DESC
            LIMIT 100
            """,
            (user_id,),
        )
        rows = cur.fetchall()

    return [
        {
            "id": str(r[0]),
            "content": r[1] or "",
            "image_url": r[2],
            "created_at": r[3],
            "likes": r[4],
            "author_id": str(r[5]),
            "author_name": r[6] or "Élève",
            "author_class": r[7] or "",
            "liked_by_me": bool(r[8]),
        }
        for r in rows
    ]


@app.post("/api/posts", status_code=201)
def create_post(
    data: PostRequest,
    current_user: dict = Depends(get_current_user),
):
    if not data.content.strip() and not data.image_url:
        raise HTTPException(
            status_code=400,
            detail="La publication est vide.",
        )

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO posts
                (author_id, content, image_url, likes, created_at)
            VALUES (%s, %s, %s, 0, NOW())
            RETURNING id, content, image_url, created_at, author_id
            """,
            (
                current_user["user_id"],
                data.content.strip(),
                data.image_url,
            ),
        )
        row = cur.fetchone()

    return {
        "status": "ok",
        "post": {
            "id": str(row[0]),
            "content": row[1],
            "image_url": row[2],
            "created_at": row[3],
            "likes": 0,
            "author_id": str(row[4]),
        },
    }


@app.post("/api/posts/{post_id}/like")
def like_post(
    post_id: str,
    current_user: dict = Depends(get_current_user),
):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT author_id FROM posts WHERE id = %s",
            (post_id,),
        )
        post = cur.fetchone()

        if not post:
            raise HTTPException(
                status_code=404,
                detail="Publication introuvable.",
            )

        cur.execute(
            """
            INSERT INTO post_likes (post_id, user_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (post_id, current_user["user_id"]),
        )

        if str(post[0]) != str(current_user["user_id"]):
            cur.execute(
                """
                INSERT INTO notifications
                    (receiver_id, sender_id, type, post_id, is_read, created_at)
                VALUES (%s, %s, 'like', %s, FALSE, NOW())
                """,
                (
                    post[0],
                    current_user["user_id"],
                    post_id,
                ),
            )

        cur.execute(
            "SELECT COUNT(*) FROM post_likes WHERE post_id = %s",
            (post_id,),
        )
        count = cur.fetchone()[0]

    return {
        "status": "ok",
        "liked": True,
        "likes": count,
    }


@app.delete("/api/posts/{post_id}/like")
def unlike_post(
    post_id: str,
    current_user: dict = Depends(get_current_user),
):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM post_likes
            WHERE post_id = %s AND user_id = %s
            """,
            (post_id, current_user["user_id"]),
        )

        cur.execute(
            "SELECT COUNT(*) FROM post_likes WHERE post_id = %s",
            (post_id,),
        )
        count = cur.fetchone()[0]

    return {
        "status": "ok",
        "liked": False,
        "likes": count,
    }


# ------------------------------------------------------------
# Signalements de publications
# ------------------------------------------------------------

@app.post("/api/posts/{post_id}/report", status_code=201)
def report_post(
    post_id: str,
    data: ReportRequest,
    current_user: dict = Depends(get_current_user),
):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO reports
                (post_id, reporter_id, reason, status, created_at)
            VALUES (%s, %s, %s, 'pending', NOW())
            ON CONFLICT DO NOTHING
            """,
            (
                post_id,
                current_user["user_id"],
                data.reason.strip(),
            ),
        )

    return {
        "status": "ok",
        "message": "Signalement envoyé.",
    }


# ------------------------------------------------------------
# Pokes
# ------------------------------------------------------------

@app.post("/api/poke/{receiver_id}", status_code=201)
def create_poke(
    receiver_id: str,
    current_user: dict = Depends(get_current_user),
):
    sender_id = current_user["user_id"]

    if str(sender_id) == str(receiver_id):
        raise HTTPException(
            status_code=400,
            detail="Tu ne peux pas t'envoyer un poke à toi-même.",
        )

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM pokes
            WHERE sender_id = %s
              AND receiver_id = %s
              AND created_at >= date_trunc('day', NOW())
            """,
            (sender_id, receiver_id),
        )

        if cur.fetchone()[0] >= 2:
            raise HTTPException(
                status_code=429,
                detail="Limite de 2 pokes.",
            )

        cur.execute(
            """
            INSERT INTO pokes
                (sender_id, receiver_id, created_at, is_read)
            VALUES (%s, %s, NOW(), FALSE)
            """,
            (sender_id, receiver_id),
        )

        cur.execute(
            """
            INSERT INTO notifications
                (receiver_id, sender_id, type, is_read, created_at)
            VALUES (%s, %s, 'poke', FALSE, NOW())
            """,
            (receiver_id, sender_id),
        )

    return {
        "status": "ok",
        "message": "Poke envoyé.",
    }


@app.get("/api/pokes/count/{user_id}")
def get_pokes_count(user_id: str):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM pokes WHERE receiver_id = %s",
            (user_id,),
        )
        count = cur.fetchone()[0]

    return {
        "user_id": user_id,
        "count": count,
    }


# ------------------------------------------------------------
# Notifications
# ------------------------------------------------------------

@app.get("/api/notifications")
def get_notifications(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                n.id, n.type, n.post_id, n.created_at,
                u.prenom, u.nom
            FROM notifications n
            JOIN users u ON u.id = n.sender_id
            WHERE n.receiver_id = %s
              AND n.is_read = FALSE
            ORDER BY n.created_at DESC
            """,
            (current_user["user_id"],),
        )
        rows = cur.fetchall()

    return [
        {
            "id": str(r[0]),
            "type": r[1],
            "post_id": str(r[2]) if r[2] else None,
            "created_at": r[3],
            "sender_name": f"{r[4]} {r[5]}",
        }
        for r in rows
    ]


@app.post("/api/notifications/read")
def mark_notifications_read(current_user: dict = Depends(get_current_user)):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE notifications
            SET is_read = TRUE
            WHERE receiver_id = %s
              AND is_read = FALSE
            """,
            (current_user["user_id"],),
        )

    return {"status": "ok"}


# ------------------------------------------------------------
# Avis et retours des élèves
# ------------------------------------------------------------

@app.get("/api/feedback")
def get_feedback():
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                f.id, f.type, f.message, f.created_at,
                u.id, u.nom, u.prenom, u.classe
            FROM feedbacks f
            JOIN users u ON u.id = f.user_id
            ORDER BY f.created_at DESC
            LIMIT 200
            """
        )
        rows = cur.fetchall()

    return [
        {
            "id": str(r[0]),
            "type": r[1],
            "message": r[2],
            "created_at": r[3],
            "user_id": str(r[4]),
            "nom": r[5],
            "prenom": r[6],
            "classe": r[7],
        }
        for r in rows
    ]


@app.post("/api/feedback", status_code=201)
def create_feedback(
    data: FeedbackRequest,
    current_user: dict = Depends(get_current_user),
):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO feedbacks
                (user_id, type, message, status, created_at)
            VALUES (%s, %s, %s, 'new', NOW())
            RETURNING id
            """,
            (
                current_user["user_id"],
                data.type,
                data.message.strip(),
            ),
        )

    return {"status": "ok"}


# ============================================================
# BACK-OFFICE ADMINISTRATEUR
# ============================================================

# La route de connexion sert à vérifier le secret administrateur.
# Toutes les routes de données ci-dessous utilisent Depends(verify_admin).


@app.post("/api/admin/login")
def admin_login(data: AdminLoginRequest):
    if not ADMIN_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail="Le mot de passe administrateur n'est pas configuré dans .env.",
        )

    if not hmac.compare_digest(data.password, ADMIN_PASSWORD):
        raise HTTPException(
            status_code=401,
            detail="Mot de passe administrateur incorrect.",
        )

    return {
        "status": "ok",
        "message": "Connexion administrateur réussie.",
    }


@app.get("/api/admin/stats", dependencies=[Depends(verify_admin)])
def admin_stats():
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM users")
        users_total = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM users
            WHERE last_seen >= NOW() - INTERVAL '5 minutes'
            """
        )
        users_online = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM posts")
        posts_total = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(*) FROM reports WHERE status = 'pending'"
        )
        pending_reports = cur.fetchone()[0]

    return {
        "users_total": users_total,
        "users_online": users_online,
        "posts_total": posts_total,
        "pending_reports": pending_reports,
    }


@app.get("/api/admin/users", dependencies=[Depends(verify_admin)])
def admin_users():
    """
    Liste des élèves et de leur dernière activité.

    to_jsonb(u)->>'created_at' permet de lire la date d'inscription
    si cette colonne existe, sans faire échouer la requête si elle
    est absente de la version actuelle de la table users.
    """

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                u.id,
                u.nom,
                u.prenom,
                u.classe,
                u.email,
                to_jsonb(u)->>'created_at' AS signup_date,
                (
                    u.last_seen IS NOT NULL
                    AND u.last_seen >= NOW() - INTERVAL '5 minutes'
                ) AS is_online,
                u.last_seen
            FROM users u
            ORDER BY
                COALESCE(to_jsonb(u)->>'created_at', '') DESC,
                u.prenom,
                u.nom
            """
        )
        rows = cur.fetchall()

    return [
        {
            "id": str(r[0]),
            "nom": r[1],
            "prenom": r[2],
            "classe": r[3],
            "email": r[4],
            "created_at": r[5],
            "is_online": bool(r[6]),
            "last_seen": r[7],
        }
        for r in rows
    ]


@app.get("/api/admin/posts", dependencies=[Depends(verify_admin)])
def admin_posts():
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                p.id,
                p.content,
                p.image_url,
                p.created_at,
                p.author_id,
                TRIM(CONCAT(u.prenom, ' ', u.nom)) AS author_name,
                u.classe AS author_class
            FROM posts p
            LEFT JOIN users u ON u.id = p.author_id
            ORDER BY p.created_at DESC
            """
        )
        rows = cur.fetchall()

    return [
        {
            "id": str(r[0]),
            "content": r[1] or "",
            "image_url": r[2],
            "created_at": r[3],
            "author_id": str(r[4]) if r[4] else None,
            "author_name": r[5] or "Élève inconnu",
            "author_class": r[6] or "",
        }
        for r in rows
    ]


@app.delete(
    "/api/admin/posts/{post_id}",
    dependencies=[Depends(verify_admin)],
)
def admin_delete_post(post_id: str):
    """
    Supprime la publication et ses références éventuelles dans les
    likes, signalements et notifications, pour éviter les erreurs
    liées aux clés étrangères.
    """

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM posts WHERE id = %s",
            (post_id,),
        )
        post = cur.fetchone()

        if not post:
            raise HTTPException(
                status_code=404,
                detail="Publication introuvable ou déjà supprimée.",
            )

        cur.execute(
            "DELETE FROM post_likes WHERE post_id = %s",
            (post_id,),
        )

        cur.execute(
            "DELETE FROM reports WHERE post_id = %s",
            (post_id,),
        )

        cur.execute(
            "DELETE FROM notifications WHERE post_id = %s",
            (post_id,),
        )

        cur.execute(
            "DELETE FROM posts WHERE id = %s",
            (post_id,),
        )

    return {
        "status": "ok",
        "message": "Publication supprimée.",
        "post_id": post_id,
    }