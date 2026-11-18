from datetime import timedelta

import click

from .db import get_db, transaction
from .security import audit, hash_password, iso, utcnow
from .validators import validate_email, validate_password, validate_person_name, validate_student_id


def register(app):
    @app.cli.command("create-admin")
    @click.option("--email", prompt=True)
    @click.option("--name", prompt="Full name")
    @click.option("--student-id", default="ADMIN001", show_default=True)
    @click.password_option()
    def create_admin(email, name, student_id, password):
        """Create an election office administrator."""
        email, e1 = validate_email(email)
        name, e2 = validate_person_name(name)
        sid, e3 = validate_student_id(student_id)
        e4 = validate_password(password, email, sid)
        problems = [e for e in (e1, e2, e3, e4) if e]
        if problems:
            raise click.ClickException(" ".join(problems))
        with transaction() as db:
            cur = db.execute(
                "INSERT INTO users (student_id, email, full_name, password_hash, role, created_at)"
                " VALUES (?, ?, ?, ?, 'admin', ?)",
                (sid, email, name, hash_password(password), iso(utcnow())),
            )
            audit("admin_created", f"user={cur.lastrowid}", cur.lastrowid)
        click.echo(f"Admin created: {email}")

    @app.cli.command("seed-demo")
    def seed_demo():
        """Load a demo voter roll and a live election (development only)."""
        names = ["Amani Njoroge", "Brian Otieno", "Chiara Wanjiru", "David Mutua", "Esther Achieng",
                 "Faith Kamau", "Grace Mwangi", "Hassan Omar", "Irene Chebet", "Joseph Kiptoo"]
        with transaction() as db:
            db.executemany(
                "INSERT OR IGNORE INTO voter_roll (student_id, full_name) VALUES (?, ?)",
                [(f"DEMO{i:04d}", n) for i, n in enumerate(names, start=1)],
            )
            now = utcnow()
            cur = db.execute(
                "INSERT INTO elections (title, description, opens_at, closes_at, launched, created_at)"
                " VALUES (?, ?, ?, ?, 1, ?)",
                ("Student Council President", "Demo election. One vote per student.",
                 iso(now - timedelta(minutes=1)), iso(now + timedelta(days=7)), iso(now)),
            )
            db.executemany(
                "INSERT INTO candidates (election_id, name, manifesto) VALUES (?, ?, ?)",
                [(cur.lastrowid, "Wanjiku Kariuki", "Longer library hours and quiet study rooms."),
                 (cur.lastrowid, "Omar Abdalla", "Reliable campus Wi-Fi in every building."),
                 (cur.lastrowid, "Lucy Atieno", "Affordable meals and a student emergency fund.")],
            )
        click.echo("Demo roll: register with student IDs DEMO0001 to DEMO0010.")
