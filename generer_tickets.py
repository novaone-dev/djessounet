from pathlib import Path
import os
import secrets
import string
import sys

import psycopg
from dotenv import load_dotenv

# Charger le fichier .env situé à côté de ce script
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")

# Lettres majuscules et chiffres
CHARACTERS = string.ascii_uppercase + string.digits

# Nombre de tickets à créer
TICKET_COUNT = 15

def generate_ticket_code() -> str:
    """Génère un code au format DJ-XXX-XX."""

    first_part = "".join(
        secrets.choice(CHARACTERS) for _ in range(3)
    )
    second_part = "".join(
        secrets.choice(CHARACTERS) for _ in range(2)
    )

    return f"DJ-{first_part}-{second_part}"

def main() -> None:
    if not DATABASE_URL:
        print(
            "Erreur : DATABASE_URL est absente de ton fichier .env."
        )
        sys.exit(1)

    inserted_codes = []
    attempts = 0
    max_attempts = 1000

    try:
        # La connexion est automatiquement fermée.
        # Les insertions sont validées si tout se passe bien.
        with psycopg.connect(
            DATABASE_URL,
            connect_timeout=10,
        ) as connection:
            with connection.cursor() as cursor:

                while len(inserted_codes) < TICKET_COUNT:
                    attempts += 1

                    if attempts > max_attempts:
                        raise RuntimeError(
                            "Impossible de générer 15 codes uniques. "
                            "Réessaie plus tard."
                        )

                    code = generate_ticket_code()

                    # Évite les doublons à l'intérieur de cette génération.
                    if code in inserted_codes:
                        continue

                    cursor.execute(
                        """
                        INSERT INTO tickets (code, is_used)
                        VALUES (%s, FALSE)
                        ON CONFLICT (code) DO NOTHING
                        RETURNING code;
                        """,
                        (code,),
                    )

                    row = cursor.fetchone()

                    # N'ajoute le code à la liste que si
                    # la base confirme qu'il a été inséré.
                    if row is not None:
                        inserted_codes.append(row[0])

        # Le bloc de connexion est terminé :
        # les tickets ont été validés dans la base.
        print()
        print(f"{len(inserted_codes)} tickets créés avec succès.")
        print("-" * 35)

        for code in inserted_codes:
            print(code)

        print("-" * 35)
        print("Conserve ces codes et distribue-les individuellement.")

    except psycopg.Error:
        print(
            "Erreur PostgreSQL : connexion ou insertion impossible. "
            "Vérifie l'URL Neon et la structure de la table tickets."
        )
        sys.exit(1)

    except RuntimeError as error:
        print(f"Erreur : {error}")
        sys.exit(1)

if __name__ == "__main__":
    main()