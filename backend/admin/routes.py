from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, send_file, current_app
from ..db import get_db_connection
import os
import pandas as pd
import psycopg2
import base64
import json
import re
from werkzeug.utils import secure_filename
from PIL import Image
from weasyprint import HTML
from io import BytesIO
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from flask import request
from collections import Counter
from ..description import letter_descriptions, preferred_program_map, short_letter_descriptions
from math import ceil
from groq import Groq
import smtplib
from email.message import EmailMessage
import random
import time

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

admin_bp = Blueprint('admin', __name__, template_folder='../../frontend/templates/admin')

DEFAULT_ADMIN = {
    "id": "1000",
    "fullname": "hertzkin",
    "username": "hk",
    "password": "hk",
    "campus": "Kabankalan Campus"

}

ALLOWED_EXTENSIONS = {"xlsx", "xls"}

UPLOAD_FOLDER = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "uploads"
)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def is_password_strong(pw):
    return (
        len(pw) >= 8 and
        re.search(r"[A-Z]", pw) and
        re.search(r"[a-z]", pw) and
        re.search(r"[0-9]", pw) and
        re.search(r"[^A-Za-z0-9]", pw)
    )

def image_to_base64(filename):
    path = os.path.join(
        current_app.static_folder,
        "images",
        filename
    )
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()
    
def student_photo_to_base64(filename):
    if not filename:
        return None

    path = os.path.join(
        current_app.static_folder,
        "uploads",
        "students",
        filename
    )

    if not os.path.exists(path):
        return None

    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()
    
def format_ai_explanation_for_pdf(text):
    if not text:
        return ""

    sections = [
        "Career Letter Explanation",
        "Strengths",
        "Weaknesses",
        "Personalized Career Advice",
        "Recommended Courses or Subjects"
    ]

    formatted = re.sub(r"\n{3,}", "\n\n", text).strip()

    for title in sections:
        formatted = re.sub(
            rf"\b{re.escape(title)}\b",
            f"<div class='font-bold uppercase'>{title}</div>",
            formatted,
            flags=re.IGNORECASE
        )

    formatted = formatted.replace("\n", "<br>")

    return formatted

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)

def send_security_alert(ip, username):
    msg = EmailMessage()
    msg["Subject"] = "⚠️ Admin Login Alert"
    msg["From"] = "aspirematch2@gmail.com"
    msg["To"] = "hertzkin@gmail.com"

    msg.set_content(f"""
    Suspicious admin login detected.

    Username: {username}
    IP Address: {ip}
    Time: {datetime.now(timezone.utc)}
    """)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login("aspirematch2@gmail.com", "bvti ptud ebch pmee")
        smtp.send_message(msg)

def generate_otp():
    """Generate a 6-digit OTP as a string."""
    return str(random.randint(100000, 999999))


def send_otp_email(email, otp):
    """Send OTP email to admin."""
    msg = EmailMessage()
    msg["Subject"] = "AspireMatch Admin OTP"
    msg["From"] = "aspirematch2@gmail.com"
    msg["To"] = email
    msg.set_content(f"""
Your One-Time Password (OTP) for AspireMatch Admin login is:

{otp}

This OTP will expire in 5 minutes.
""")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login("aspirematch2@gmail.com", "bvti ptud ebch pmee")
        server.send_message(msg)

@admin_bp.route("/test-db")
def test_db():
    conn = get_db_connection()
    return "DB CONNECTED"

@admin_bp.route("/")
def home():
    return redirect(url_for("admin.login"))

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None 

    # Initialize
    session.setdefault("admin_login_attempts", 0)
    session.setdefault("admin_lock_until", None)

    # Check lockout
    if session["admin_lock_until"]:
        if datetime.now(timezone.utc) < session["admin_lock_until"]:
            remaining = int(
                (session["admin_lock_until"] - datetime.now(timezone.utc)).total_seconds() / 60
            )
            error = f"Account locked. Try again in {remaining} minutes."
            return render_template("admin/adminLogin.html", error=error)
        else:
            # Unlock
            session["admin_login_attempts"] = 0
            session["admin_lock_until"] = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin = cur.fetchone()
        cur.close()
        conn.close()

        if admin and check_password_hash(admin["password"], password):
            session.clear()
            session["admin_username"] = username
            session["admin_login_attempts"] = 0
            session["admin_lock_until"] = None

            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT campus FROM admin WHERE username=%s", (username,))
                admin_campus = cur.fetchone()[0]

                cur.execute("""
                    INSERT INTO admin_logs (admin_username, campus, action)
                    VALUES (%s, %s, %s)
                """, (username, admin_campus, "Admin logged in"))

                conn.commit()
                cur.close()
                conn.close()
            except Exception as e:
                print("Failed to log admin login:", e)

            return redirect(url_for("admin.dashboard"))

        if username == DEFAULT_ADMIN["username"] and password == DEFAULT_ADMIN["password"]:
            session.clear()
            session["admin_username"] = username
            session["admin_login_attempts"] = 0
            session["admin_lock_until"] = None

            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO admin_logs (admin_username, campus, action)
                    VALUES (%s, %s, %s)
                """, (username, "ALL", "Super admin logged in"))
                conn.commit()
                cur.close()
                conn.close()
            except Exception as e:
                print("Failed to log super admin login:", e)
                
            return redirect(url_for("admin.dashboard"))

        ip = request.headers.get("X-Forwarded-For", request.remote_addr)

        # Track IP in database
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO admin_login_attempts (ip_address, username, attempts)
            VALUES (%s, %s, 1)
            ON CONFLICT (ip_address)
            DO UPDATE SET
                attempts = admin_login_attempts.attempts + 1,
                last_attempt = CURRENT_TIMESTAMP
        """, (ip, username))
        conn.commit()
        cur.close()
        conn.close()

        session["admin_login_attempts"] += 1

        if session["admin_login_attempts"] == MAX_LOGIN_ATTEMPTS:
            send_security_alert(ip, username)

        if session["admin_login_attempts"] >= MAX_LOGIN_ATTEMPTS:
            session["admin_lock_until"] = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
            error = "Too many failed attempts. Account locked for 15 minutes."
        else:
            remaining = MAX_LOGIN_ATTEMPTS - session["admin_login_attempts"]
            error = f"Invalid credentials. {remaining} attempts remaining."

    locked = session.get("admin_login_attempts", 0) >= MAX_LOGIN_ATTEMPTS

    return render_template("admin/adminLogin.html", error=error, locked=locked)

@admin_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    error = success = None

    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM admin WHERE email = %s", (email,))
        admin = cur.fetchone()
        cur.close()
        conn.close()

        if not admin:
            error = "No admin account found with this email."
        else:
            otp = generate_otp()

            session["admin_otp"] = otp
            session["admin_otp_email"] = email
            session["admin_otp_time"] = time.time()

            send_otp_email(email, otp)
            success = "OTP has been sent to your email."

            return redirect(url_for("admin.verify_reset_otp"))

    return render_template(
        "admin/adminForgotPassword.html",
        error=error,
        success=success
    )

@admin_bp.route("/verify-reset-otp", methods=["GET", "POST"])
def verify_reset_otp():
    error = None
    success = None
    remaining = None
    
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT fullname, campus FROM admin WHERE username = %s;",
        (session["admin_username"],)
    )
    admin_row = cur.fetchone()

    if not admin_row:
        cur.close()
        conn.close()
        return redirect(url_for("admin.login"))

    fullname, admin_campus = admin_row

    if request.method == "POST":

        action = request.form.get("action")

        # 🔁 RESEND OTP
        if action == "resend":
            if "admin_otp_email" not in session:
                error = "Session expired. Please restart password reset."
            else:
                last_sent = session.get("admin_otp_time", 0)
                elapsed = int(time.time() - last_sent)

                if elapsed < 60:
                    remaining = 60 - elapsed
                    error = "Please wait before resending OTP."
                else:
                    otp = generate_otp()
                    session["admin_otp"] = otp
                    session["admin_otp_time"] = time.time()

                    send_otp_email(session["admin_otp_email"], otp)
                    success = "A new OTP has been sent to your email."

            return render_template(
                "admin/adminVerifyOtp.html",
                error=error,
                success=success,
                remaining=remaining   # ✅ PASS IT
            )

        if action == "verify":
            user_otp = request.form.get("otp", "").strip()

            if not user_otp:
                error = "Please enter the OTP."

            elif time.time() - session.get("admin_otp_time", 0) > 300:
                error = "OTP expired. Please request a new one."

            elif user_otp != session.get("admin_otp"):
                error = "Invalid OTP."

            else:
                session["admin_reset_email"] = session["admin_otp_email"]
                session.pop("admin_otp", None)
                session.pop("admin_otp_email", None)
                session.pop("admin_otp_time", None)
                return redirect(url_for("admin.reset_password"))

    return render_template(
        "admin/adminVerifyOtp.html",
        error=error,
        success=success,
        fullname=fullname,
        admin_campus=admin_campus
    )

@admin_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    error = None

    if "admin_reset_email" not in session:
        return redirect(url_for("admin.login"))

    if request.method == "POST":
        password = request.form["password"]
        confirm = request.form["confirm"]

        if password != confirm:
            error = "Passwords do not match."
        else:
            hashed = generate_password_hash(password)

            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE admin
                SET password = %s
                WHERE email = %s
            """, (hashed, session["admin_reset_email"]))
            conn.commit()
            cur.close()
            conn.close()

            session.pop("admin_reset_email", None)

            return redirect(url_for("admin.login"))

    return render_template("admin/adminResetPassword.html", error=error)

@admin_bp.route("/dashboard", methods=["GET"])
def dashboard():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT fullname, campus FROM admin WHERE username = %s;",
        (session["admin_username"],)
    )
    admin_row = cur.fetchone()
    if not admin_row:
        cur.close()
        conn.close()
        return redirect(url_for("admin.login"))

    fullname, admin_campus = admin_row

    # Available years
    cur.execute("""
        SELECT DISTINCT EXTRACT(YEAR FROM created_at)::int
        FROM student
        ORDER BY 1 DESC;
    """)
    available_years = [row[0] for row in cur.fetchall()]

    selected_year = request.args.get("year", type=int) or datetime.now().year

    search_query = request.args.get("q", "").strip()

    searched_students = []

    if search_query:
        cur.execute("""
            SELECT id, exam_id, fullname, gender, email
            FROM student
            WHERE campus = %s
            AND EXTRACT(YEAR FROM created_at) = %s
            AND (
                    LOWER(fullname) LIKE LOWER(%s)
                    OR exam_id ILIKE %s
                )
            ORDER BY fullname ASC;
        """, (
            admin_campus,
            selected_year,
            f"%{search_query}%",
            f"%{search_query}%"
        ))
        searched_students = cur.fetchall()

    # counts (unchanged)
    cur.execute("""
        SELECT COUNT(*)
        FROM student
        WHERE EXTRACT(YEAR FROM created_at) = %s
        AND campus = %s;
    """, (selected_year, admin_campus))
    total_students = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM student s
        LEFT JOIN student_survey_answer a
            ON a.student_id = s.id OR a.exam_id = s.exam_id
        WHERE s.campus = %s
        AND EXTRACT(YEAR FROM s.created_at) = %s
        AND (a.preferred_program IS NULL OR a.preferred_program = '');
    """, (admin_campus, selected_year))
    pending_students = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(DISTINCT admin_username)
        FROM admin_logs
        WHERE created_at >= NOW() - INTERVAL '1 month';
    """)
    active_admins = cur.fetchone()[0]

    cur.close()
    conn.close()

    return render_template(
        "admin/dashboard.html",
        admin_username=session["admin_username"],
        fullname=fullname,
        admin_campus=admin_campus,
        total_students=total_students,
        pending_students=pending_students,
        active_admins=active_admins,
        year=selected_year,
        available_years=available_years,
        searched_students=searched_students,
        search_query=search_query
    )

@admin_bp.route("/edit-student", methods=["POST"])
def edit_student():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    admin_username = session["admin_username"]

    student_id = request.form["student_id"]
    new_fullname = request.form["fullname"]
    new_gender = request.form["gender"]
    new_email = request.form["email"]

    conn = get_db_connection()
    cur = conn.cursor()

    # Get admin campus
    cur.execute(
        "SELECT campus FROM admin WHERE username = %s;",
        (admin_username,)
    )
    admin_campus = cur.fetchone()[0]

    # 🔹 Get OLD student data
    cur.execute("""
        SELECT fullname, gender, email
        FROM student
        WHERE id = %s;
    """, (student_id,))
    old_fullname, old_gender, old_email = cur.fetchone()

    # 🔹 Update student
    cur.execute("""
        UPDATE student
        SET fullname = %s,
            gender = %s,
            email = %s
        WHERE id = %s;
    """, (new_fullname, new_gender, new_email, student_id))

    # 🔹 Insert logs ONLY for changed fields
    if old_fullname != new_fullname:
        cur.execute("""
            INSERT INTO admin_logs (admin_username, campus, action)
            VALUES (%s, %s, %s);
        """, (
            admin_username,
            admin_campus,
            f"Edited student: {old_fullname} into {new_fullname}"
        ))

    if old_gender != new_gender:
        cur.execute("""
            INSERT INTO admin_logs (admin_username, campus, action)
            VALUES (%s, %s, %s);
        """, (
            admin_username,
            admin_campus,
            f"Edited student: {old_gender} into {new_gender}"
        ))

    if old_email != new_email:
        cur.execute("""
            INSERT INTO admin_logs (admin_username, campus, action)
            VALUES (%s, %s, %s);
        """, (
            admin_username,
            admin_campus,
            f"Edited student: {old_email} into {new_email}"
        ))

    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for("admin.dashboard"))

@admin_bp.route("/delete-student", methods=["POST"])
def delete_student():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    admin_username = session["admin_username"]
    student_id = request.form["student_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    # Get admin campus
    cur.execute(
        "SELECT campus FROM admin WHERE username = %s;",
        (admin_username,)
    )
    admin_campus = cur.fetchone()[0]

    # Get student fullname BEFORE delete
    cur.execute(
        "SELECT fullname FROM student WHERE id = %s;",
        (student_id,)
    )
    student_row = cur.fetchone()
    if not student_row:
        cur.close()
        conn.close()
        return redirect(url_for("admin.dashboard"))

    student_fullname = student_row[0]

    # DELETE student → cascade will remove all related records
    cur.execute(
        "DELETE FROM student WHERE id = %s;",
        (student_id,)
    )

    # Log the delete action
    cur.execute("""
        INSERT INTO admin_logs (admin_username, campus, action)
        VALUES (%s, %s, %s);
    """, (
        admin_username,
        admin_campus,
        f"Deleted student: {student_fullname}"
    ))

    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for("admin.dashboard"))

@admin_bp.route("/addAdmin", methods=["GET", "POST"])
def addAdmin():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    message = None
    category = None
    admin_username = session["admin_username"]

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT campus FROM admin WHERE username = %s", (admin_username,))
    admin_campus = cur.fetchone()[0]
    cur.close()
    conn.close()

    if request.method == "POST":
        fullname = request.form["fullname"]
        username = request.form["user_name"]
        email = request.form["email"]
        campus = request.form["campus"]
        password = request.form["password"]

        if not is_password_strong(password):
            return render_template(
                "admin/addAdmin.html",
                admin_username=session["admin_username"],
                message="Password is too weak! Must include: uppercase, lowercase, number, symbol, and min 8 chars.",
                category="danger",
                admins=[]
            )

        hashed_pw = generate_password_hash(password)

        session["new_admin_data"] = {
            "fullname": fullname,
            "username": username,
            "email": email,
            "campus": campus,
            "password": hashed_pw
        }

        # 🔢 GENERATE OTP
        otp = generate_otp()
        session["new_admin_otp"] = otp
        session["new_admin_otp_time"] = time.time()
        session["new_admin_email"] = email

        # 📧 SEND OTP
        send_otp_email(email, otp)

        return redirect(url_for("admin.verify_new_admin"))

    admins = []
    if session["admin_username"] == "hkml":
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, fullname, username, email, campus
            FROM admin
            ORDER BY campus ASC, fullname ASC
        """)
        admins = cur.fetchall()
        cur.close()
        conn.close()

    deleted_admins = []
    if session["admin_username"] == "hkml":
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, fullname, username, email, campus, deleted_by, deleted_at
            FROM deleted_admin
            ORDER BY deleted_at DESC
        """)
        deleted_admins = cur.fetchall()
        cur.close()
        conn.close()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT program_name, created_at, is_active
        FROM program
        WHERE campus = %s
        ORDER BY created_at DESC
    """, (admin_campus,))
    programs = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "admin/addAdmin.html",
        admin_username=session["admin_username"],
        message=message,
        category=category,
        admins=admins,
        programs=programs,
        admin_campus=admin_campus,
        deleted_admins=deleted_admins
    )

@admin_bp.route("/delete-admin", methods=["POST"])
def delete_admin():
    if "admin_username" not in session or session["admin_username"] != "hkml":
        return redirect(url_for("admin.login"))

    deleted_admin_id = request.form["admin_id"]
    new_admin_id = request.form["reassign_admin_id"]
    deleter = session["admin_username"]

    conn = get_db_connection()
    cur = conn.cursor()

    # 🔹 Get admin to be deleted
    cur.execute("""
        SELECT id, fullname, username, email, campus
        FROM admin
        WHERE id = %s
    """, (deleted_admin_id,))
    admin_row = cur.fetchone()

    if not admin_row:
        cur.close()
        conn.close()
        return redirect(url_for("admin.addAdmin"))

    admin_id, fullname, username, email, campus = admin_row

    # ❌ Prevent deleting self
    if username == deleter:
        cur.close()
        conn.close()
        return redirect(url_for("admin.addAdmin"))

    # 🔹 Get NEW admin username (for logs)
    cur.execute("""
        SELECT username
        FROM admin
        WHERE id = %s
    """, (new_admin_id,))
    new_admin_username = cur.fetchone()[0]

    # 🔁 Reassign students
    cur.execute("""
        UPDATE student
        SET added_by = %s
        WHERE added_by = %s
    """, (new_admin_id, admin_id))

    # 🗃 Save deleted admin snapshot
    cur.execute("""
        INSERT INTO deleted_admin
        (id, fullname, username, email, campus, deleted_by)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        admin_id, fullname, username, email, campus, deleter
    ))

    # ❌ Delete admin
    cur.execute("DELETE FROM admin WHERE id = %s", (admin_id,))

    # 🧾 Admin logs (UPDATED MESSAGE)
    cur.execute("""
        INSERT INTO admin_logs (admin_username, campus, action)
        VALUES (%s, %s, %s)
    """, (
        deleter,
        campus,
        f"Deleted admin: {fullname} ({username}) and reassigned students into admin {new_admin_username}"
    ))

    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for("admin.addAdmin"))

@admin_bp.route("/verify-new-admin", methods=["GET", "POST"])
def verify_new_admin():
    error = None
    success = None
    remaining = None

    if "new_admin_email" not in session:
        return redirect(url_for("admin.addAdmin"))

    if request.method == "POST":
        action = request.form.get("action")

        # 🔁 RESEND OTP
        if action == "resend":
            elapsed = int(time.time() - session.get("new_admin_otp_time", 0))

            if elapsed < 60:
                remaining = 60 - elapsed
                error = "Please wait before resending OTP."
            else:
                otp = generate_otp()
                session["new_admin_otp"] = otp
                session["new_admin_otp_time"] = time.time()
                send_otp_email(session["new_admin_email"], otp)
                success = "A new OTP has been sent."

        # ✅ VERIFY OTP
        if action == "verify":
            user_otp = request.form.get("otp", "").strip()

            if not user_otp:
                error = "Please enter the OTP."
            elif time.time() - session["new_admin_otp_time"] > 300:
                error = "OTP expired."
            elif user_otp != session["new_admin_otp"]:
                error = "Invalid OTP."
            else:
                # 🎉 CREATE ADMIN ACCOUNT
                data = session["new_admin_data"]

                conn = get_db_connection()
                cur = conn.cursor()

                cur.execute("""
                    INSERT INTO admin (fullname, username, email, campus, password)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    data["fullname"],
                    data["username"],
                    data["email"],
                    data["campus"],
                    data["password"]
                ))

                cur.execute("""
                    INSERT INTO admin_logs (admin_username, campus, action)
                    VALUES (%s, %s, %s)
                """, (
                    session["admin_username"],
                    data["campus"],
                    f"Added new admin '{data['username']}' (email verified)"
                ))

                conn.commit()
                cur.close()
                conn.close()

                # 🧹 CLEAN SESSION
                session.pop("new_admin_data", None)
                session.pop("new_admin_otp", None)
                session.pop("new_admin_otp_time", None)
                session.pop("new_admin_email", None)

                return redirect(url_for("admin.addAdmin", success="verified"))

    return render_template(
        "admin/adminVerifyOtp.html",
        error=error,
        success=success,
        remaining=remaining
    )

@admin_bp.route("/admin_logs/<username>")
def get_admin_logs(username):
    if "admin_username" not in session:
        return jsonify([])

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT admin_username, action, created_at
        FROM admin_logs
        WHERE admin_username = %s
        ORDER BY created_at DESC
    """, (username,))

    logs = cur.fetchall()
    cur.close()
    conn.close()

    return jsonify([
        {
            "admin_username": log[0],
            "action": log[1],
            "created_at": log[2].strftime("%Y-%m-%d %H:%M")
        }
        for log in logs
    ])

@admin_bp.route("/editAdmin", methods=["POST"])
def editAdmin():
    if "admin_username" not in session:
        return jsonify(success=False, message="Unauthorized")

    data = request.get_json()
    admin_id = data.get("id")
    fullname = data.get("fullname")
    username = data.get("username")
    email = data.get("email")
    campus = data.get("campus")

    if not admin_id:
        return jsonify(success=False, message="Missing admin ID")

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ ADDED: Get old data for comparison
        cur.execute("""
            SELECT fullname, username, email, campus
            FROM admin
            WHERE id = %s
        """, (admin_id,))
        old = cur.fetchone()

        if not old:
            return jsonify(success=False, message="Admin not found")

        old_fullname, old_username, old_email, old_campus = old

        # ✅ ADDED: Detect changes
        changes = []

        if fullname != old_fullname:
            changes.append(f"fullname '{old_fullname}' → '{fullname}'")

        if username != old_username:
            changes.append(f"username '{old_username}' → '{username}'")

        if email != old_email:
            changes.append(f"email '{old_email}' → '{email}'")

        if campus != old_campus:
            changes.append(f"campus '{old_campus}' → '{campus}'")

        if not changes:
            return jsonify(success=False, message="No changes detected")

        # Update admin
        cur.execute("""
            UPDATE admin
            SET fullname=%s, username=%s, email=%s, campus=%s
            WHERE id=%s
        """, (fullname, username, email, campus, admin_id))

        # Get editor campus for logs
        cur.execute("""
            SELECT campus FROM admin WHERE username = %s
        """, (session["admin_username"],))
        admin_campus = cur.fetchone()[0]

        # ✅ CHANGED: Smart log message
        action = f"Edited admin '{old_username}': " + ", ".join(changes)

        cur.execute("""
            INSERT INTO admin_logs (admin_username, campus, action)
            VALUES (%s, %s, %s)
        """, (
            session["admin_username"],
            admin_campus,
            action
        ))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify(success=True)

    except psycopg2.Error as e:
        return jsonify(success=False, message=str(e))

@admin_bp.route("/addProgram", methods=["POST"])
def addProgram():
    if "admin_username" not in session:
        return jsonify(success=False, message="Unauthorized")

    program_name = request.form.get("program_name")
    campus = request.form.get("campus")
    category_letters = request.form.get("category_letters")
    category_descriptions = request.form.get("category_descriptions")

    if not category_letters or not category_descriptions:
        return jsonify(success=False, message="Select at least one category")

    if not program_name or not campus:
        return jsonify(success=False, message="Missing data")

    admin_username = session["admin_username"]

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT campus FROM admin WHERE username = %s",
            (admin_username,)
        )
        admin_campus = cur.fetchone()[0]

        cur.execute("""
            INSERT INTO program (program_name, campus, category_letter, category_description)
            VALUES (%s, %s, %s, %s)
        """, (
            program_name,
            campus,
            category_letters,
            category_descriptions
        ))

        cur.execute("""
            INSERT INTO admin_logs (admin_username, campus, action)
            VALUES (%s, %s, %s)
        """, (
            admin_username,
            admin_campus,
            f"Added new program '{program_name}'"
        ))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify(success=True)

    except Exception as e:
        return jsonify(success=False, message=str(e))
    
@admin_bp.route("/addProgramColor", methods=["POST"])
def addProgramColor():
    if "admin_username" not in session:
        return jsonify(success=False, message="Unauthorized")

    data = request.get_json()
    program_name = data.get("program_name")
    color = data.get("color")

    if not program_name or not color:
        return jsonify(success=False, message="Missing data")

    admin_username = session["admin_username"]

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Get admin campus
        cur.execute("SELECT campus FROM admin WHERE username = %s", (admin_username,))
        admin_campus = cur.fetchone()[0]

        # Update program color
        cur.execute("""
            UPDATE program
            SET color = %s
            WHERE program_name = %s
        """, (color, program_name))

        # Log the action
        cur.execute("""
            INSERT INTO admin_logs (admin_username, campus, action)
            VALUES (%s, %s, %s)
        """, (
            admin_username,
            admin_campus,
            f"Set color '{color}' for program '{program_name}'"
        ))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify(success=True)

    except Exception as e:
        return jsonify(success=False, message=str(e))

@admin_bp.route("/program")
def program():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    admin_username = session["admin_username"]

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT campus FROM admin WHERE username = %s", (admin_username,))
    admin_campus = cur.fetchone()[0]

    cur.execute("""
        SELECT id, program_name, created_at, is_active, color
        FROM program
        WHERE campus = %s
        ORDER BY created_at DESC
    """, (admin_campus,))
    programs = cur.fetchall()

    cur.close()
    conn.close()

    if request.args.get("ajax"):
        return render_template("admin/_program_rows.html", programs=programs)

    return render_template(
        "admin/program.html",
        admin_username=admin_username,
        programs=programs,
        admin_campus=admin_campus
    )

@admin_bp.route("/editProgram", methods=["POST"])
def editProgram():
    if "admin_username" not in session:
        return jsonify(success=False, message="Unauthorized")

    data = request.get_json()
    program_id = data.get("id")
    new_name = data.get("name")
    new_color = data.get("color")

    if not program_id or (not new_name and not new_color):
        return jsonify(success=False, message="Missing data")

    admin_username = session["admin_username"]

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Get admin campus
        cur.execute("SELECT campus FROM admin WHERE username = %s", (admin_username,))
        admin_campus = cur.fetchone()[0]

        # Get current program values
        cur.execute("SELECT program_name, color FROM program WHERE id = %s", (program_id,))
        row = cur.fetchone()
        if not row:
            return jsonify(success=False, message="Program not found")
        old_name, old_color = row

        # Determine which fields are changing
        fields_to_update = []
        params = []

        action_parts = []

        if new_name and new_name != old_name:
            fields_to_update.append("program_name = %s")
            params.append(new_name)
            action_parts.append(f"Edited program '{old_name}' → '{new_name}'")

        if new_color and new_color != old_color:
            fields_to_update.append("color = %s")
            params.append(new_color)
            action_parts.append(f"Edited program color '{old_color}' → '{new_color}'")

        if not fields_to_update:
            return jsonify(success=False, message="No changes detected")

        params.append(program_id)

        # Update program
        sql = f"UPDATE program SET {', '.join(fields_to_update)} WHERE id = %s"
        cur.execute(sql, params)

        # Log the action
        action_text = "; ".join(action_parts)  # combine multiple changes with semicolon
        cur.execute("""
            INSERT INTO admin_logs (admin_username, campus, action)
            VALUES (%s, %s, %s)
        """, (admin_username, admin_campus, action_text))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify(success=True)

    except Exception as e:
        return jsonify(success=False, message=str(e))

@admin_bp.route("/addParticipant", methods=["POST"])
def addParticipant():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    fullname = request.form["full_name"]
    exam_id = request.form["exam_id"]
    gender = request.form["gender"]
    email = request.form["email"]

    admin_username = session["admin_username"]

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Get admin ID and campus
        cur.execute(
            "SELECT id, campus FROM admin WHERE username = %s",
            (admin_username,)
        )
        admin = cur.fetchone()

        if not admin:
            flash("Admin not found", "danger")
            return redirect(url_for("admin.dashboard"))

        admin_id, admin_campus = admin

        # Check duplicate student
        cur.execute(
            "SELECT 1 FROM student WHERE exam_id = %s OR email = %s",
            (exam_id, email)
        )
        if cur.fetchone():
            flash("❌ Examination ID or Email already exists!", "danger")
            return redirect(url_for("admin.dashboard"))

        # Insert student
        cur.execute("""
            INSERT INTO student 
                (fullname, exam_id, gender, email, campus, added_by)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            fullname,
            exam_id,
            gender,
            email,
            admin_campus,
            admin_id
        ))

        # Insert admin log
        cur.execute("""
            INSERT INTO admin_logs (admin_username, campus, action)
            VALUES (%s, %s, %s)
        """, (
            admin_username,
            admin_campus,
            f"Added new student '{fullname}'"
        ))

        conn.commit()
        cur.close()
        conn.close()

        return render_template(
            "dashboard.html",
            manual_success=True,
            manual_message="Participant added successfully!"
        )

    except Exception as e:
        flash(f"⚠️ Error: {str(e)}", "danger")
        return redirect(url_for("admin.dashboard"))

@admin_bp.route("/upload", methods=["POST"])
def upload():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    if "file" not in request.files:
        return render_template("dashboard.html", error="No file part")

    file = request.files["file"]

    if file.filename == "":
        return render_template("dashboard.html", error="No selected file")

    if not allowed_file(file.filename):
        return render_template(
            "dashboard.html",
            error="Only Excel files (.xlsx, .xls) are allowed"
        )

    admin_username = session["admin_username"]

    try:
        df = pd.read_excel(file, dtype=str)
        df.columns = df.columns.str.lower().str.strip()

        required_cols = {"fullname", "exam_id", "gender", "email"}
        if not required_cols.issubset(df.columns):
            return render_template(
                "dashboard.html",
                error="Excel must contain columns: fullname, exam_id, gender, email"
            )

        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Get admin ID + campus
        cur.execute(
            "SELECT id, campus FROM admin WHERE username = %s",
            (admin_username,)
        )
        admin = cur.fetchone()

        if not admin:
            return render_template("dashboard.html", error="Admin not found")

        admin_id, admin_campus = admin

        inserted = 0
        skipped = 0

        for _, row in df.iterrows():
            fullname = (row.get("fullname") or "").strip()
            exam_id = (row.get("exam_id") or "").strip()
            gender = (row.get("gender") or "").strip()
            email = (row.get("email") or "").strip()

            if not fullname or not exam_id or not email:
                skipped += 1
                continue

            cur.execute(
                "SELECT 1 FROM student WHERE exam_id = %s",
                (exam_id,)
            )
            if cur.fetchone():
                skipped += 1
                continue

            # ✅ Insert student
            cur.execute("""
                INSERT INTO student
                    (fullname, exam_id, gender, email, campus, added_by)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                fullname,
                exam_id,
                gender,
                email,
                admin_campus,
                admin_id
            ))

            inserted += 1

        # 📝 Insert admin log ONLY if something was added
        if inserted > 0:
            cur.execute("""
                INSERT INTO admin_logs (admin_username, campus, action)
                VALUES (%s, %s, %s)
            """, (
                admin_username,
                admin_campus,
                f"Added {inserted} new student through excel"
            ))

        conn.commit()
        cur.close()
        conn.close()

        return render_template(
            "dashboard.html",
            upload_success=True,
            upload_message=f"Upload complete! Inserted: {inserted}, Skipped: {skipped}"
        )

    except Exception as e:
        return render_template(
            "dashboard.html",
            error=f"Error reading Excel file: {str(e)}"
        )

PER_PAGE = 10

@admin_bp.route("/respondents")
def respondents():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute(
        "SELECT id, campus FROM admin WHERE username = %s",
        (session["admin_username"],)
    )
    admin = cur.fetchone()

    if not admin:
        cur.close()
        conn.close()
        return redirect(url_for("admin.login"))

    admin_id, admin_campus = admin

    cur.execute("SELECT DISTINCT EXTRACT(YEAR FROM created_at)::int FROM student ORDER BY 1 DESC;")
    available_years = [row[0] for row in cur.fetchall()]

    selected_year = request.args.get("year", type=int)
    if not selected_year:
        selected_year = datetime.now().year

    search_query = request.args.get("q", "")
    status_filter = request.args.get("status", "")
    page = request.args.get("page", 1, type=int) 

    cur.execute("""
        SELECT s.exam_id, s.fullname, sa.preferred_program,
               sa.pair1, sa.pair2, sa.pair3, sa.pair4, sa.pair5,
               sa.pair6, sa.pair7, sa.pair8, sa.pair9, sa.pair10,
               sa.pair11, sa.pair12, sa.pair13, sa.pair14, sa.pair15,
               sa.pair16, sa.pair17, sa.pair18, sa.pair19, sa.pair20,
               sa.pair21, sa.pair22, sa.pair23, sa.pair24, sa.pair25,
               sa.pair26, sa.pair27, sa.pair28, sa.pair29, sa.pair30,
               sa.pair31, sa.pair32, sa.pair33, sa.pair34, sa.pair35,
               sa.pair36, sa.pair37, sa.pair38, sa.pair39, sa.pair40,
               sa.pair41, sa.pair42, sa.pair43, sa.pair44, sa.pair45,
               sa.pair46, sa.pair47, sa.pair48, sa.pair49, sa.pair50,
               sa.pair51, sa.pair52, sa.pair53, sa.pair54, sa.pair55,
               sa.pair56, sa.pair57, sa.pair58, sa.pair59, sa.pair60,
               sa.pair61, sa.pair62, sa.pair63, sa.pair64, sa.pair65,
               sa.pair66, sa.pair67, sa.pair68, sa.pair69, sa.pair70,
               sa.pair71, sa.pair72, sa.pair73, sa.pair74, sa.pair75,
               sa.pair76, sa.pair77, sa.pair78, sa.pair79, sa.pair80,
               sa.pair81, sa.pair82, sa.pair83, sa.pair84, sa.pair85,
               sa.pair86
        FROM student s
        LEFT JOIN student_survey_answer sa ON s.exam_id = sa.exam_id
        WHERE EXTRACT(YEAR FROM s.created_at) = %s
        AND (s.campus = %s OR s.added_by = %s)
        AND (%s = '' OR s.fullname ILIKE %s)
        ORDER BY s.fullname ASC; 
    """, (
            selected_year,
            admin_campus,
            admin_id,
            search_query,
            f"%{search_query}%"
        ))

    raw_students = cur.fetchall()
    students = []

    for row in raw_students:
        exam_id, fullname, preferred_program, *pairs = row

        answers_clean = [p for p in pairs if p]
        top_letters = [letter for letter, _ in Counter(answers_clean).most_common(3)]
        program_letters = []

        if preferred_program:
            cur.execute("SELECT category_letter FROM program WHERE program_name = %s", (preferred_program,))
            result = cur.fetchone()
            if result:
                program_letters = result[0].split(",")

        # determine match
        if not preferred_program and not answers_clean:
            match_status = "——"
        elif any(letter in program_letters for letter in top_letters):
            match_status = "✔️ Match"
        else:
            match_status = "❌ Not Match"

        students.append((exam_id, fullname, preferred_program, match_status))

    cur.close()
    conn.close()

    # apply status filter
    if status_filter == "match":
        students = [s for s in students if s[3] == "✔️ Match"]
    elif status_filter == "not_match":
        students = [s for s in students if s[3] == "❌ Not Match"]

    total_students = len(students)
    total_pages = ceil(total_students / PER_PAGE)
    start = (page - 1) * PER_PAGE
    end = start + PER_PAGE
    students_paginated = students[start:end]

    return render_template(
        "admin/respondents.html",
        admin_username=session["admin_username"],
        admin_campus=admin_campus,
        available_years=available_years,
        year=selected_year,
        students=students_paginated,
        search_query=search_query,
        status_filter=status_filter,
        page=page,
        total_pages=total_pages
    )

@admin_bp.route("/adminSurveyResult")
def adminSurveyResult():
    exam_id = request.args.get("exam_id")
    if not exam_id:
        flash("Invalid request. No Exam ID provided.")
        return redirect(url_for("admin.dashboard"))

    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute(
        "SELECT id, campus FROM admin WHERE username = %s",
        (session["admin_username"],)
    )
    admin = cur.fetchone()

    if not admin:
        cur.close()
        conn.close()
        return redirect(url_for("admin.login"))

    admin_id, admin_campus = admin

    cur.execute("""
        SELECT s.exam_id, s.fullname, s.created_at, s.campus, s.photo, 
               sa.preferred_program, sa.ai_explanation,
               sa.pair1, sa.pair2, sa.pair3, sa.pair4, sa.pair5,
               sa.pair6, sa.pair7, sa.pair8, sa.pair9, sa.pair10,
               sa.pair11, sa.pair12, sa.pair13, sa.pair14, sa.pair15,
               sa.pair16, sa.pair17, sa.pair18, sa.pair19, sa.pair20,
               sa.pair21, sa.pair22, sa.pair23, sa.pair24, sa.pair25,
               sa.pair26, sa.pair27, sa.pair28, sa.pair29, sa.pair30,
               sa.pair31, sa.pair32, sa.pair33, sa.pair34, sa.pair35,
               sa.pair36, sa.pair37, sa.pair38, sa.pair39, sa.pair40,
               sa.pair41, sa.pair42, sa.pair43, sa.pair44, sa.pair45,
               sa.pair46, sa.pair47, sa.pair48, sa.pair49, sa.pair50,
               sa.pair51, sa.pair52, sa.pair53, sa.pair54, sa.pair55,
               sa.pair56, sa.pair57, sa.pair58, sa.pair59, sa.pair60,
               sa.pair61, sa.pair62, sa.pair63, sa.pair64, sa.pair65,
               sa.pair66, sa.pair67, sa.pair68, sa.pair69, sa.pair70,
               sa.pair71, sa.pair72, sa.pair73, sa.pair74, sa.pair75,
               sa.pair76, sa.pair77, sa.pair78, sa.pair79, sa.pair80,
               sa.pair81, sa.pair82, sa.pair83, sa.pair84, sa.pair85,
               sa.pair86
        FROM student s
        LEFT JOIN student_survey_answer sa ON s.exam_id = sa.exam_id
        WHERE s.exam_id = %s;
    """, (exam_id,))
    
    row = cur.fetchone()

    if not row:
        return "No survey results found."

    created_at = row[2]

    start_year = created_at.year
    end_year = start_year + 1
    year = f"{start_year}-{end_year}"

    student_results = {
        "exam_id": row[0],
        "fullname": row[1],
        "created_at": row[2],
        "campus": row[3],
        "photo": row[4],
        "preferred_program": row[5],
        "ai_explanation": format_ai_explanation_for_pdf(row[6]),
        "answers": [row[i] for i in range(7, 93)]
    }

    answers_clean = student_results["answers"]
    preferred = student_results["preferred_program"]  # <- ALWAYS define it

    top_letters = []
    program_letters = []

    if answers_clean:
        # get top 3 chosen letters
        letter_counts = Counter(answers_clean)
        top_letters = [letter for letter, _ in letter_counts.most_common(3)]

    if preferred:
        # get category_letter from program table
        cur.execute("SELECT category_letter FROM program WHERE program_name = %s", (preferred,))
        result = cur.fetchone()
        program_letters = result[0].split(",") if result else []

    # determine match
    if not preferred and not answers_clean:
        match_status = "Not Yet Answer"
    elif any(letter in program_letters for letter in top_letters):
        match_status = "Match"
    else:
        match_status = "Not Match"

    conn.close()

    return render_template(
        "admin/adminSurveyResult.html",
        admin_username=session["admin_username"],
        admin_campus=admin_campus,
        student_results=student_results,
        student_campus=student_results["campus"],
        top_letters=top_letters,
        letter_descriptions=letter_descriptions,
        match_status=match_status,
        year=year
    )

@admin_bp.route('/download_result/<exam_id>')
def download_result(exam_id):
    if not exam_id:
        flash("Invalid request.")
        return redirect(url_for('admin.dashboard'))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT s.exam_id, s.fullname, s.created_at, s.campus, s.photo,
               sa.preferred_program, sa.ai_explanation,
               sa.pair1, sa.pair2, sa.pair3, sa.pair4, sa.pair5,
               sa.pair6, sa.pair7, sa.pair8, sa.pair9, sa.pair10,
               sa.pair11, sa.pair12, sa.pair13, sa.pair14, sa.pair15,
               sa.pair16, sa.pair17, sa.pair18, sa.pair19, sa.pair20,
               sa.pair21, sa.pair22, sa.pair23, sa.pair24, sa.pair25,
               sa.pair26, sa.pair27, sa.pair28, sa.pair29, sa.pair30,
               sa.pair31, sa.pair32, sa.pair33, sa.pair34, sa.pair35,
               sa.pair36, sa.pair37, sa.pair38, sa.pair39, sa.pair40,
               sa.pair41, sa.pair42, sa.pair43, sa.pair44, sa.pair45,
               sa.pair46, sa.pair47, sa.pair48, sa.pair49, sa.pair50,
               sa.pair51, sa.pair52, sa.pair53, sa.pair54, sa.pair55,
               sa.pair56, sa.pair57, sa.pair58, sa.pair59, sa.pair60,
               sa.pair61, sa.pair62, sa.pair63, sa.pair64, sa.pair65,
               sa.pair66, sa.pair67, sa.pair68, sa.pair69, sa.pair70,
               sa.pair71, sa.pair72, sa.pair73, sa.pair74, sa.pair75,
               sa.pair76, sa.pair77, sa.pair78, sa.pair79, sa.pair80,
               sa.pair81, sa.pair82, sa.pair83, sa.pair84, sa.pair85,
               sa.pair86
        FROM student s
        LEFT JOIN student_survey_answer sa ON s.exam_id = sa.exam_id
        WHERE s.exam_id = %s;
    """, (exam_id,))

    row = cur.fetchone()
    conn.close()

    if not row:
        return "Survey results not found", 404

    created_at = row[2]

    start_year = created_at.year
    end_year = start_year + 1
    year = f"{start_year}-{end_year}"

    student_data = {
        "exam_id": row[0],
        "fullname": row[1],
        "created_at": row[2],
        "campus": row[3],
        "photo": row[4],
        "preferred_program": row[5],
        "ai_explanation": format_ai_explanation_for_pdf(row[6]),
        "answers": [row[i] for i in range(7, 93)]
    }

    answers_clean = [a for a in student_data["answers"] if a]
    letter_counts = Counter(answers_clean)
    top_letters = [l for l, _ in letter_counts.most_common(3)]

    preferred = student_data["preferred_program"]
    if not preferred and not answers_clean:
        match_status = "Not Yet Answer"
    elif preferred in preferred_program_map and any(
        l in preferred_program_map[preferred] for l in top_letters
    ):
        match_status = "Match"
    else:
        match_status = "Not Match"

    cpsu_logo = image_to_base64("cpsulogo.png")
    bagong_logo = image_to_base64("bagong-pilipinas-logo.png")
    safe_logo = image_to_base64("logo.png")

    html = render_template(
        "admin/adminSurveyResultPDF.html",
        student_data=student_data,
        top_letters=top_letters,
        match_status=match_status,
        student_campus=student_data["campus"],
        letter_descriptions=letter_descriptions,
        year=year,
        cpsu_logo_base64=cpsu_logo,
        bagong_logo_base64=bagong_logo,
        safe_logo_base64=safe_logo
    )

    pdf_io = BytesIO()
    HTML(string=html, base_url=current_app.root_path).write_pdf(pdf_io)
    pdf_io.seek(0)

    filename = f"Career_Survey_Result_{student_data['fullname']}.pdf"

    return send_file(
        pdf_io,
        mimetype="application/pdf",
        download_name=filename,
        as_attachment=True
    )

PER_PAGE = 10

@admin_bp.route("/adminInventory")
def adminInventory():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    cur.execute(
        "SELECT id, campus FROM admin WHERE username = %s",
        (session["admin_username"],)
    )
    admin = cur.fetchone()

    if not admin:
        cur.close()
        conn.close()
        return redirect(url_for("admin.login"))

    admin_id, admin_campus = admin

    cur.execute("""
        SELECT DISTINCT EXTRACT(YEAR FROM created_at)::int 
        FROM student 
        ORDER BY 1 DESC;
    """)
    available_years = [row[0] for row in cur.fetchall()]

    selected_year = request.args.get("year", type=int)
    if not selected_year:
        selected_year = datetime.now().year

    search_query = request.args.get("q", "")
    page = request.args.get("page", 1, type=int)

    cur.execute("""
        SELECT 
            s.id AS id,
            s.exam_id, 
            s.fullname,
            COALESCE(f.father_income, 0) + COALESCE(f.mother_income, 0) AS total_income
        FROM student s
        LEFT JOIN family_background f 
            ON f.student_id = s.id
        WHERE EXTRACT(YEAR FROM s.created_at) = %s
        AND (s.campus = %s OR s.added_by = %s)
        AND (%s = '' OR s.fullname ILIKE %s)
        -- Sorting handled in Python instead of SQL
        ORDER BY s.fullname ASC;
    """, (
            selected_year,
            admin_campus,
            admin_id,
            search_query,
            f"%{search_query}%"
        ))

    students = cur.fetchall()

    sort = request.args.get("sort", "default")

    classified_students = []
    for id, exam_id, fullname, total_income in students:
        if total_income == 0:
            category = "____"
            income_display = None
        else:
            income_display = total_income

            if total_income <= 10000:
                category = "Low Income"
            elif total_income <= 20000:
                category = "Lower-Middle"
            elif total_income <= 40000:
                category = "Middle"
            elif total_income <= 80000:
                category = "Middle-Upper"
            else:
                category = "High Income"

        classified_students.append((id, exam_id, fullname, income_display, category))

    def sorting_key(item):
        id, exam_id, fullname, income, category = item

        no_income = (income is None)

        if sort == "income_asc":
            return income if income is not None else 999999999

        if sort == "income_desc":
            return -income if income is not None else float("-inf")

        if sort == "name_asc":
            return fullname.lower()

        if sort == "name_desc":
            return fullname.lower()[::-1]

        if sort == "category_asc":
            return (category == "____", category)

        if sort == "category_desc":
            return (category == "____", category[::-1])

        return exam_id
    
    classified_students.sort(key=sorting_key)

    cur.close()
    conn.close()

    total_students = len(classified_students)
    total_pages = max(1, ceil(total_students / PER_PAGE))
    start = (page - 1) * PER_PAGE
    end = start + PER_PAGE
    students_paginated = classified_students[start:end]

    return render_template(
        "admin/adminInventory.html",
        admin_username=session["admin_username"],
        admin_campus=admin_campus,
        available_years=available_years,
        year=selected_year,
        students=students_paginated,
        search_query=search_query,
        page=page,
        total_pages=total_pages,
        sort=sort
    )

@admin_bp.route("/adminInventoryResult")
def adminInventoryResult():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    student_id = request.args.get("student_id")
    if not student_id:
        flash("Invalid request. No student ID provided.")
        return redirect(url_for("admin.adminInventory"))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    cur.execute(
        "SELECT id, campus FROM admin WHERE username = %s",
        (session["admin_username"],)
    )
    admin = cur.fetchone()

    if not admin:
        cur.close()
        conn.close()
        return redirect(url_for("admin.login"))

    admin_id, admin_campus = admin

    cur.execute("""
        SELECT 
            s.id AS id,
            s.fullname, s.gender, s.email, s.campus, s.photo,
            sa.nickname, sa.present_address, sa.provincial_address,
            sa.date_of_birth, sa.place_of_birth, sa.age, sa.birth_order, sa.siblings_count,
            sa.civil_status, sa.religion, sa.nationality,
            sa.home_phone, sa.mobile_no, sa.email AS personal_email,
            sa.weight, sa.height, sa.blood_type, sa.hobbies, sa.talents,
            sa.emergency_name, sa.emergency_relationship, sa.emergency_address, sa.emergency_contact,
            sb.father_name, sb.father_age, sb.father_education, sb.father_occupation,
            sb.father_income, sb.father_contact, sb.mother_name, sb.mother_age, sb.mother_education,
            sb.mother_occupation, sb.mother_income, sb.mother_contact, 
            sc.married_living_together, sc.living_not_married, sc.legally_separated,
            sc.mother_widow, sc.father_widower, sc.separated, sc.father_another_family, sc.mother_another_family,
            sd.elementary_school_name, sd.elementary_year_graduated, sd.elementary_awards,
            sd.junior_high_school_name, sd.junior_high_year_graduated, sd.junior_high_awards,
            sd.senior_high_school_name, sd.senior_high_year_graduated, sd.senior_high_awards,
            sd.senior_high_track, sd.senior_high_strand, sd.subject_interested, sd.org_membership,
            sd.study_finance, sd.course_personal_choice, sd.influenced_by, sd.feeling_about_course, sd.personal_choice,
            se.bullying, se.bullying_when, se.bullying_bother,
            se.suicidal_thoughts, se.suicidal_thoughts_when, se.suicidal_thoughts_bother,
            se.suicidal_attempts, se.suicidal_attempts_when, se.suicidal_attempts_bother,
            se.panic_attacks, se.panic_attacks_when, se.panic_attacks_bother,
            se.anxiety, se.anxiety_when, se.anxiety_bother,
            se.depression, se.depression_when, se.depression_bother,
            se.self_anger_issues, se.self_anger_issues_when, se.self_anger_issues_bother,
            se.recurring_negative_thoughts, se.recurring_negative_thoughts_when, se.recurring_negative_thoughts_bother,
            se.low_self_esteem, se.low_self_esteem_when, se.low_self_esteem_bother,
            se.poor_study_habits, se.poor_study_habits_when, se.poor_study_habits_bother,
            se.poor_in_decision_making, se.poor_in_decision_making_when, se.poor_in_decision_making_bother,
            se.impulsivity, se.impulsivity_when, se.impulsivity_bother,
            se.poor_sleeping_habits, se.poor_sleeping_habits_when, se.poor_sleeping_habits_bother,
            se.loos_of_appetite, se.loos_of_appetite_when, se.loos_of_appetite_bother,
            se.over_eating, se.over_eating_when, se.over_eating_bother,
            se.poor_hygiene, se.poor_hygiene_when, se.poor_hygiene_bother,
            se.withdrawal_isolation, se.withdrawal_isolation_when, se.withdrawal_isolation_bother,
            se.family_problem, se.family_problem_when, se.family_problem_bother,
            se.other_relationship_problem, se.other_relationship_problem_when, se.other_relationship_problem_bother,
            se.alcohol_addiction, se.alcohol_addiction_when, se.alcohol_addiction_bother,
            se.gambling_addiction, se.gambling_addiction_when, se.gambling_addiction_bother,
            se.drug_addiction, se.drug_addiction_when, se.drug_addiction_bother,
            se.computer_addiction, se.computer_addiction_when, se.computer_addiction_bother,
            se.sexual_harassment, se.sexual_harassment_when, se.sexual_harassment_bother,
            se.sexual_abuse, se.sexual_abuse_when, se.sexual_abuse_bother,
            se.physical_abuse, se.physical_abuse_when, se.physical_abuse_bother,
            se.verbal_abuse, se.verbal_abuse_when, se.verbal_abuse_bother,
            se.pre_marital_sex, se.pre_marital_sex_when, se.pre_marital_sex_bother,
            se.teenage_pregnancy, se.teenage_pregnancy_when, se.teenage_pregnancy_bother,
            se.abortion, se.abortion_when, se.abortion_bother,
            se.extra_marital_affairs, se.extra_marital_affairs_when, se.extra_marital_affairs_bother,
            sf.psychiatrist_before, sf.psychiatrist_reason, sf.psychiatrist_when,
            sf.psychologist_before, sf.psychologist_reason, sf.psychologist_when,
            sf.counselor_before, sf.counselor_reason, sf.counselor_when,
            sg.personal_description
        FROM student s
        LEFT JOIN personal_information sa ON sa.student_id = s.id
        LEFT JOIN family_background sb ON sb.student_id = s.id
        LEFT JOIN status_of_parent sc ON sc.student_id = s.id
        LEFT JOIN academic_information sd ON sd.student_id = s.id
        LEFT JOIN behavior_information se ON se.student_id = s.id
        LEFT JOIN psychological_consultations sf ON sf.student_id = s.id
        LEFT JOIN personal_descriptions sg ON sg.student_id = s.id
        WHERE s.id = %s
    """, (student_id,))

    info = cur.fetchone()

    student_photo_base64 = None

    if info and info["photo"]:
        student_photo_base64 = student_photo_to_base64(info["photo"])

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT reasons, other_reason
        FROM cpsu_enrollment_reason
        WHERE student_id = %s
    """, (student_id,))
    enroll_reason = cur.fetchone()

    cur.execute("""
        SELECT school_choices, other_school
        FROM other_schools_considered
        WHERE student_id = %s
    """, (student_id,))
    other_school_data = cur.fetchone()

    cur.close()
    conn.close()

    selected_reasons = []
    other_reason = ""
    if enroll_reason:
        if enroll_reason[0]:
            selected_reasons = [r.strip() for r in enroll_reason[0].split(",")]
        other_reason = enroll_reason[1] or ""

    other_schools_selected = []
    other_school = ""
    if other_school_data:
        if other_school_data[0]:
            other_schools_selected = [r.strip() for r in other_school_data[0].split(",")]
        other_school = other_school_data[1] or ""

    return render_template(
        "admin/adminInventoryResult.html",
        admin_username=session["admin_username"],
        admin_campus=admin_campus,
        info=info,
        student_photo_base64=student_photo_base64,
        selected_reasons=selected_reasons,
        other_reason=other_reason,
        other_schools_selected=other_schools_selected,
        other_school=other_school
    )

@admin_bp.route('/download_admin_inventory_pdf/<int:student_id>')
def download_admin_inventory_pdf(student_id):
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT 
            s.id AS id,
            s.fullname, s.gender, s.email, s.campus, s.photo,
            sa.nickname, sa.present_address, sa.provincial_address,
            sa.date_of_birth, sa.place_of_birth, sa.age, sa.birth_order, sa.siblings_count,
            sa.civil_status, sa.religion, sa.nationality,
            sa.home_phone, sa.mobile_no, sa.email AS personal_email,
            sa.weight, sa.height, sa.blood_type, sa.hobbies, sa.talents,
            sa.emergency_name, sa.emergency_relationship, sa.emergency_address, sa.emergency_contact,
            sb.father_name, sb.father_age, sb.father_education, sb.father_occupation,
            sb.father_income, sb.father_contact, sb.mother_name, sb.mother_age, sb.mother_education,
            sb.mother_occupation, sb.mother_income, sb.mother_contact,
            sc.married_living_together, sc.living_not_married, sc.legally_separated,
            sc.mother_widow, sc.father_widower, sc.separated, sc.father_another_family, sc.mother_another_family,
            sd.elementary_school_name, sd.elementary_year_graduated, sd.elementary_awards,
            sd.junior_high_school_name, sd.junior_high_year_graduated, sd.junior_high_awards,
            sd.senior_high_school_name, sd.senior_high_year_graduated, sd.senior_high_awards,
            sd.senior_high_track, sd.senior_high_strand, sd.subject_interested, sd.org_membership,
            sd.study_finance, sd.course_personal_choice, sd.influenced_by,
            sd.feeling_about_course, sd.personal_choice,
            se.*, sf.*, sg.personal_description
        FROM student s
        LEFT JOIN personal_information sa ON sa.student_id = s.id
        LEFT JOIN family_background sb ON sb.student_id = s.id
        LEFT JOIN status_of_parent sc ON sc.student_id = s.id
        LEFT JOIN academic_information sd ON sd.student_id = s.id
        LEFT JOIN behavior_information se ON se.student_id = s.id
        LEFT JOIN psychological_consultations sf ON sf.student_id = s.id
        LEFT JOIN personal_descriptions sg ON sg.student_id = s.id
        WHERE s.id = %s
    """, (student_id,))

    info = cur.fetchone()
    if not info:
        return "Student Inventory results not found.", 404

    cur.execute("""
        SELECT reasons, other_reason
        FROM cpsu_enrollment_reason
        WHERE student_id = %s
    """, (student_id,))
    enroll_reason = cur.fetchone()

    cur.execute("""
        SELECT school_choices, other_school
        FROM other_schools_considered
        WHERE student_id = %s
    """, (student_id,))
    other_school_data = cur.fetchone()

    cur.close()
    conn.close()

    selected_reasons = enroll_reason[0].split(",") if enroll_reason and enroll_reason[0] else []
    other_reason = enroll_reason[1] if enroll_reason else ""

    other_schools_selected = other_school_data[0].split(",") if other_school_data and other_school_data[0] else []
    other_school = other_school_data[1] if other_school_data else ""

    cpsu_logo_base64 = image_to_base64("cpsulogo.png")

    html = render_template(
        "admin/adminInventoryResultPDF.html",
        admin_username=session["admin_username"],
        info=info,
        selected_reasons=selected_reasons,
        other_reason=other_reason,
        other_schools_selected=other_schools_selected,
        other_school=other_school,
        cpsu_logo_base64=cpsu_logo_base64
    )

    pdf_io = BytesIO()
    HTML(string=html, base_url=current_app.root_path).write_pdf(pdf_io)
    pdf_io.seek(0)

    filename = f"Inventory_{info['fullname'].replace(' ', '_')}.pdf"

    return send_file(
        pdf_io,
        mimetype="application/pdf",
        download_name=filename,
        as_attachment=True
    )

@admin_bp.route("/generateInterviewAI/<int:student_id>")
def generateInterviewAI(student_id):
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT questions FROM interview_questions WHERE student_id = %s",
            (student_id,)
        )
        existing = cur.fetchone()

        if existing:
            return jsonify(existing[0])

        cur.execute("""
            SELECT 
                s.fullname,
                sa.preferred_program,
                sa.pair1, sa.pair2, sa.pair3, sa.pair4, sa.pair5,
                sa.pair6, sa.pair7, sa.pair8, sa.pair9, sa.pair10,
                sa.pair11, sa.pair12, sa.pair13, sa.pair14, sa.pair15,
                sa.pair16, sa.pair17, sa.pair18, sa.pair19, sa.pair20,
                sa.pair21, sa.pair22, sa.pair23, sa.pair24, sa.pair25,
                sa.pair26, sa.pair27, sa.pair28, sa.pair29, sa.pair30,
                sa.pair31, sa.pair32, sa.pair33, sa.pair34, sa.pair35,
                sa.pair36, sa.pair37, sa.pair38, sa.pair39, sa.pair40,
                sa.pair41, sa.pair42, sa.pair43, sa.pair44, sa.pair45,
                sa.pair46, sa.pair47, sa.pair48, sa.pair49, sa.pair50,
                sa.pair51, sa.pair52, sa.pair53, sa.pair54, sa.pair55,
                sa.pair56, sa.pair57, sa.pair58, sa.pair59, sa.pair60,
                sa.pair61, sa.pair62, sa.pair63, sa.pair64, sa.pair65,
                sa.pair66, sa.pair67, sa.pair68, sa.pair69, sa.pair70,
                sa.pair71, sa.pair72, sa.pair73, sa.pair74, sa.pair75,
                sa.pair76, sa.pair77, sa.pair78, sa.pair79, sa.pair80,
                sa.pair81, sa.pair82, sa.pair83, sa.pair84, sa.pair85,
                sa.pair86
            FROM student s
            LEFT JOIN student_survey_answer sa ON s.id = sa.student_id
            WHERE s.id = %s
        """, (student_id,))

        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Student not found"}), 404

        fullname = row[0]
        preferred_program = row[1]
        letters = [l for l in row[2:] if l]

        if not letters:
            return jsonify({"error": "No survey answers"}), 400

        # ---------- PROGRAM LETTERS ----------
        program_letters = []
        if preferred_program:
            cur.execute(
                "SELECT category_letter FROM program WHERE program_name = %s",
                (preferred_program,)
            )
            res = cur.fetchone()
            if res and res[0]:
                program_letters = [x.strip() for x in res[0].split(",")]

        # ---------- ANALYSIS ----------
        counts = Counter(letters)
        top_three = [l for l, _ in counts.most_common(3)]

        top_three_descriptions = [
            short_letter_descriptions.get(l, "Unknown")
            for l in top_three
        ]

        all_letter_descriptions = [
            short_letter_descriptions.get(l, "Unknown")
            for l in letters
        ]

        program_descriptions = [
            short_letter_descriptions.get(l, "Unknown")
            for l in program_letters
        ]

        prompt = f"""
You are an educational guidance AI.

Student: {fullname}
Preferred Program: {preferred_program}

Program Category Letters: {program_letters}
Program Descriptions: {program_descriptions}

Student Top 3 Letters: {top_three}
Top 3 Descriptions: {top_three_descriptions}

All 86 Answers (Letters): {letters}
All 86 Answers (Descriptions): {all_letter_descriptions}

Use ONLY the descriptions from short_letter_descriptions.
Do NOT use Holland RIASEC.
Do NOT invent traits.

Explain alignment or mismatch by comparing:
- Program category letters + descriptions
- Student top 3 letters + descriptions

Use ONLY provided descriptions.
Return JSON ONLY.

{{
  "questions": ["q1","q2","q3","q4","q5","q6"],
  "mismatch_reason": "Explain clearly",
  "talking_points": ["p1","p2","p3"]
}}
"""

        # ---------- GROQ AI ----------
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "Return ONLY valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1000
        )

        raw = response.choices[0].message.content.strip()

        import re, json
        match = re.search(r"\{.*\}", raw, re.S)
        if not match:
            raise ValueError("Invalid JSON from AI")

        data = json.loads(match.group())

        # ---------- SAVE ----------
        cur.execute(
            "INSERT INTO interview_questions (student_id, questions) VALUES (%s, %s)",
            (student_id, json.dumps(data))
        )
        conn.commit()

        return jsonify(data)

    except Exception as e:
        conn.rollback()
        print("ERROR:", e)
        return jsonify({"error": "AI generation failed"}), 500

    finally:
        cur.close()
        conn.close()

PER_PAGE = 10

@admin_bp.route("/interviewList")
def interviewList():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute(
        "SELECT id, campus FROM admin WHERE username = %s",
        (session["admin_username"],)
    )
    admin = cur.fetchone()

    if not admin:
        cur.close()
        conn.close()
        return redirect(url_for("admin.login"))

    admin_id, admin_campus = admin

    cur.execute("""
        SELECT DISTINCT EXTRACT(YEAR FROM created_at)::int 
        FROM student 
        ORDER BY 1 DESC;
    """)
    available_years = [row[0] for row in cur.fetchall()]

    selected_year = request.args.get("year", type=int) or datetime.now().year

    search_query = request.args.get("q", "")

    page = request.args.get("page", 1, type=int)

    cur.execute("""
        SELECT 
            s.id,
            s.exam_id,
            s.fullname,
            sa.preferred_program,
            sa.pair1, sa.pair2, sa.pair3, sa.pair4, sa.pair5,
            sa.pair6, sa.pair7, sa.pair8, sa.pair9, sa.pair10,
            sa.pair11, sa.pair12, sa.pair13, sa.pair14, sa.pair15,
            sa.pair16, sa.pair17, sa.pair18, sa.pair19, sa.pair20,
            sa.pair21, sa.pair22, sa.pair23, sa.pair24, sa.pair25,
            sa.pair26, sa.pair27, sa.pair28, sa.pair29, sa.pair30,
            sa.pair31, sa.pair32, sa.pair33, sa.pair34, sa.pair35,
            sa.pair36, sa.pair37, sa.pair38, sa.pair39, sa.pair40,
            sa.pair41, sa.pair42, sa.pair43, sa.pair44, sa.pair45,
            sa.pair46, sa.pair47, sa.pair48, sa.pair49, sa.pair50,
            sa.pair51, sa.pair52, sa.pair53, sa.pair54, sa.pair55,
            sa.pair56, sa.pair57, sa.pair58, sa.pair59, sa.pair60,
            sa.pair61, sa.pair62, sa.pair63, sa.pair64, sa.pair65,
            sa.pair66, sa.pair67, sa.pair68, sa.pair69, sa.pair70,
            sa.pair71, sa.pair72, sa.pair73, sa.pair74, sa.pair75,
            sa.pair76, sa.pair77, sa.pair78, sa.pair79, sa.pair80,
            sa.pair81, sa.pair82, sa.pair83, sa.pair84, sa.pair85,
            sa.pair86,
            sch.schedule_date,
            sch.start_time,
            sch.end_time
        FROM student s
        LEFT JOIN student_survey_answer sa ON s.id = sa.student_id
        LEFT JOIN student_schedules ss ON s.id = ss.student_id
        LEFT JOIN schedules sch ON ss.schedule_id = sch.id
        WHERE EXTRACT(YEAR FROM s.created_at) = %s
        AND (s.campus = %s OR s.added_by = %s)
        AND (%s = '' OR s.fullname ILIKE %s)
        ORDER BY s.fullname ASC;
    """, (
            selected_year,
            admin_campus,
            admin_id,
            search_query,
            f"%{search_query}%"
        ))

    raw_students = cur.fetchall()

    students = []

    for row in raw_students:
        student_id, exam_id, fullname, preferred_program, *rest = row
        pairs = rest[:-3]
        schedule_date, start_time, end_time = rest[-3:]

        answers_clean = [p for p in pairs if p]
        top_letters = [l for l, _ in Counter(answers_clean).most_common(3)]

        program_letters = []

        if preferred_program:
            cur.execute(
                "SELECT category_letter FROM program WHERE program_name = %s",
                (preferred_program,)
            )
            res = cur.fetchone()
            if res:
                program_letters = res[0].split(",")

        if not preferred_program and not answers_clean:
            match_status = "Not Yet Answer"
        elif any(letter in program_letters for letter in top_letters):
            match_status = "Match"
        else:
            match_status = "Not Match"

        if match_status == "Not Match":
            if schedule_date:
                schedule_str = (
                    f"{schedule_date.strftime('%Y-%m-%d')} "
                    f"({start_time.strftime('%I:%M %p')} - {end_time.strftime('%I:%M %p')})"
                )
            else:
                schedule_str = None

            students.append((student_id, exam_id, fullname, schedule_str))

    cur.close()
    conn.close()

    total_students = len(students)
    total_pages = ceil(total_students / PER_PAGE)
    start = (page - 1) * PER_PAGE
    end = start + PER_PAGE
    students_paginated = students[start:end]

    return render_template(
        "admin/interviewList.html",
        admin_username=session["admin_username"],
        admin_campus=admin_campus,
        available_years=available_years,
        year=selected_year,
        students=students_paginated,
        search_query=search_query,
        page=page,
        total_pages=total_pages
    )

@admin_bp.route("/save_schedule", methods=["POST"])
def save_schedule():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    data = request.get_json()
    schedule_date = data.get("date")
    start_time = data.get("start_time")
    end_time = data.get("end_time")
    slot_count = data.get("slot_count")

    admin_username = session["admin_username"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # 🔍 Get admin campus
        cur.execute(
            "SELECT campus FROM admin WHERE username = %s",
            (admin_username,)
        )
        admin_campus = cur.fetchone()[0]

        # Check duplicate schedule
        cur.execute(
            "SELECT 1 FROM schedules WHERE schedule_date = %s",
            (schedule_date,)
        )
        if cur.fetchone():
            return jsonify({
                "status": "error",
                "error": "A schedule already exists for this date."
            }), 400

        # Insert schedule
        cur.execute("""
            INSERT INTO schedules
                (schedule_date, start_time, end_time, slot_count, admin_username)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            schedule_date,
            start_time,
            end_time,
            slot_count,
            admin_username
        ))

        # Insert admin log
        cur.execute("""
            INSERT INTO admin_logs (admin_username, campus, action)
            VALUES (%s, %s, %s)
        """, (
            admin_username,
            admin_campus,
            f"Added new interview date '{schedule_date}'"
        ))

        conn.commit()

        return jsonify({
            "status": "success",
            "message": "Schedule saved successfully!"
        }), 200

    except psycopg2.Error as e:
        conn.rollback()
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

    finally:
        cur.close()
        conn.close()

@admin_bp.route("/visualization") 
def visualization():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    conn = get_db_connection()
    cur = conn.cursor()

    # Get logged-in admin campus
    cur.execute(
        "SELECT campus FROM admin WHERE username = %s;",
        (session["admin_username"],)
    )
    admin_campus = cur.fetchone()[0]

    # Fetch available years for students in this campus
    cur.execute("""
        SELECT DISTINCT EXTRACT(YEAR FROM s.created_at)::int
        FROM student s
        WHERE s.campus = %s
        ORDER BY 1 ASC;
    """, (admin_campus,))
    available_years = [row[0] for row in cur.fetchall()]

    # Fetch all programs with ID and name
    cur.execute("SELECT id, program_name, color FROM program ORDER BY id ASC;")
    all_programs = cur.fetchall()  # list of tuples (id, program_name)

    current_year = datetime.now().year
    selected_year = request.args.get("year", str(current_year))
    selected_gender = request.args.get("gender", "All")

    def fetch_data_for_year(year=None, gender=None):
        params = [admin_campus]  # first param is campus filter
        filters = ["s.campus = %s"]  # add campus filter

        if year is not None:
            filters.append("EXTRACT(YEAR FROM s.created_at) = %s")
            params.append(year)

        if gender and gender != "All":
            filters.append("LOWER(s.gender) = LOWER(%s)")
            params.append(gender)

        where_clause = "WHERE " + " AND ".join(filters) if filters else ""

        # Count preferred programs
        cur.execute(f"""
            SELECT COALESCE(ssa.preferred_program, 'Unknown') AS program, COUNT(*)
            FROM student_survey_answer ssa
            JOIN student s ON ssa.student_id = s.id
            {where_clause}
            GROUP BY COALESCE(ssa.preferred_program, 'Unknown')
            ORDER BY COUNT(*) DESC;
        """, tuple(params))
        preferred_data = cur.fetchall()
        preferred_labels = [row[0] for row in preferred_data]
        preferred_counts = [row[1] for row in preferred_data]

        cur.execute(f"""
            SELECT 
                COALESCE(ssa.preferred_program, 'Unknown') AS program,
                LOWER(s.gender) AS gender,
                COUNT(*) AS count
            FROM student_survey_answer ssa
            JOIN student s ON ssa.student_id = s.id
            {where_clause}
            GROUP BY COALESCE(ssa.preferred_program, 'Unknown'), LOWER(s.gender)
            ORDER BY program, count DESC;
        """, tuple(params))

        gender_program_rows = cur.fetchall()

        # Structure:
        # {
        #   "BACHELOR OF SCIENCE IN CRIMINOLOGY": {"male": 30, "female": 10}
        # }
        gender_program_map = {}

        for program, gender, count in gender_program_rows:
            if program not in gender_program_map:
                gender_program_map[program] = {}
            gender_program_map[program][gender] = count
            
        # Count top letters from pair1 to pair86
        letter_columns = [f"pair{i}" for i in range(1, 87)]
        union_parts = []
        for col in letter_columns:
            union_parts.append(
                f"SELECT {col} AS letter FROM student_survey_answer ssa JOIN student s ON ssa.student_id = s.id "
                f"{where_clause} AND {col} BETWEEN 'A' AND 'R'"
            )
        union_sql = " UNION ALL ".join(union_parts)
        union_params = tuple(params * len(letter_columns)) if params else ()

        cur.execute(f"""
            SELECT letter, COUNT(*) FROM ({union_sql}) t
            GROUP BY letter
            ORDER BY COUNT(*) DESC
            LIMIT 18;
        """, union_params)
        top_letters = cur.fetchall()
        top_labels = [row[0] for row in top_letters]
        top_counts = [row[1] for row in top_letters]

        return {
            "year": str(year) if year else "All",
            "gender": gender or "All",
            "preferred_labels": preferred_labels,
            "preferred_counts": preferred_counts,
            "top_labels": top_labels,
            "top_counts": top_counts,
            "gender_program_distribution": gender_program_map
        }

    if str(selected_year).lower() == "all":
        all_years_data = [fetch_data_for_year(y, selected_gender) for y in available_years]
    else:
        try:
            sy = int(selected_year)
        except:
            sy = current_year
        all_years_data = [fetch_data_for_year(sy, selected_gender)]

    cur.close()
    conn.close()

    return render_template(
        "admin/visualization.html",
        admin_username=session["admin_username"],
        admin_campus=admin_campus,
        available_years=available_years,
        year=str(selected_year),
        gender=str(selected_gender),
        all_years_data=all_years_data,
        all_programs=all_programs,
        letter_descriptions=letter_descriptions
    )

@admin_bp.route("/generate_ai_visualization_insights", methods=["POST"])
def generate_ai_visualization_insights():
    req = request.get_json()
    data = req.get("data", [])

    prompt = f"""
    You are an educational analytics AI.
    Analyze the following dataset from student survey visualizations:

    {data}

    Generate the following insights.
    IMPORTANT:
    - Make the following section titles BOLD using HTML <strong> tags:
    Yearly Trends,
    Gender-based Behaviors,
    Predicted Future Program Demand,
    Narrative Summary of Graphs,
    Academic Planning Recommendations

    1. <strong>Yearly Trends</strong>
    - Identify increases or decreases in preferred programs.
    - Identify patterns in top letters.

    2. <strong>Gender-based Behaviors</strong>
    - Explicitly mention which gender prefers which program more.
    - Use clear comparisons example:
    "More male students selected program compared to female students."
    - If differences are minimal, clearly state that preferences are balanced.
    - Mention at least ONE specific program name in this section.

    3. <strong>Predicted Future Program Demand</strong>
    - Which programs are likely to grow next year?
    - Which may decline?

    4. <strong>Narrative Summary of Graphs</strong>
    - Write like a report analyst summarizing the charts.

    5. <strong>Academic Planning Recommendations</strong>
    - Suggestions for schools based on student trends.

    STRICT FORMAT RULES:
    - Output MUST be a numbered list from 1 to 5
    - Each number must start on a NEW LINE
    - Each section title must be wrapped in <strong> tags
    - Leave ONE blank line between sections
    - Do NOT merge sections into one paragraph

    IMPORTANT:
    - Always cite at least one program name when discussing gender-based behaviors.

    Generate the insights exactly in this structure:

    1. <strong>Yearly Trends</strong>
    Short paragraph here.

    2. <strong>Gender-based Behaviors</strong>
    Short paragraph here.

    3. <strong>Predicted Future Program Demand</strong>
    Short paragraph here.

    4. <strong>Narrative Summary of Graphs</strong>
    Short paragraph here.

    5. <strong>Academic Planning Recommendations</strong>
    Short paragraph here.
    """

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    )

    insights = response.choices[0].message.content

    return jsonify({"insights": insights})

@admin_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("admin.login"))
