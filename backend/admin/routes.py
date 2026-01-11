from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, send_file, current_app
from ..db import get_db_connection
import os
import pandas as pd
import psycopg2
import base64
import json
import re
from weasyprint import HTML
from io import BytesIO
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from flask import request
from collections import Counter
from ..description import letter_descriptions, preferred_program_map, short_letter_descriptions
from math import ceil
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

admin_bp = Blueprint('admin', __name__, template_folder='../../frontend/templates/admin')

DEFAULT_ADMIN = {
    "username": "hk",
    "password": "hk",
    "firstname": "hertzkin"
}

# Allowed file extensions
ALLOWED_EXTENSIONS = {"xlsx", "xls"}

# Ensure upload folder exists
UPLOAD_FOLDER = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "uploads"
)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Blueprint-level variable (or use main app config)
# We'll register it in main app later
# In blueprint, access via current_app.config["UPLOAD_FOLDER"]

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def check_login_suspicious(username, password):
    prompt = f"""
    Analyze this login attempt:
    Username: {username}
    Password Length: {len(password)}

    Decide if this login looks suspicious.
    Mark only:
    - "safe"
    - "suspicious"
    """

    ai_response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": "You detect suspicious login patterns."},
                  {"role": "user", "content": prompt}]
    )

    return ai_response.choices[0].message.content.strip().lower()

def is_password_strong(pw):
    return (
        len(pw) >= 8 and
        re.search(r"[A-Z]", pw) and
        re.search(r"[a-z]", pw) and
        re.search(r"[0-9]", pw) and
        re.search(r"[^A-Za-z0-9]", pw)
    )

def run_sql(query):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(query)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows
    except Exception as e:
        return f"SQL Error: {str(e)}"
    
def generate_report(data):
    report_type = data.get("type", "")

    reports = {
        "weekly": "📊 Weekly Report\n• 45 students assessed\n• 12 mismatches\n• Most chosen: IT",
        "monthly": "📅 Monthly Summary\n• 120 students\n• 35 mismatches\n• Top programs: IT, EDUC",
        "yearly": "📆 Yearly Overview\n• 890 respondents\n• 260 mismatched\n• AGRI rising demand"
    }

    return reports.get(report_type, "Unknown report type")

def image_to_base64(filename):
    path = os.path.join(
        current_app.static_folder,
        "images",
        filename
    )
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()

@admin_bp.route("/test-db")
def test_db():
    conn = get_db_connection()
    return "DB CONNECTED"

@admin_bp.route("/")
def home():
    return redirect(url_for("admin.login"))

@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        ai_flag = check_login_suspicious(username, password)
        if ai_flag == "suspicious":
            flash("⚠️ Dan detected unusual login behavior. Proceed with caution.", "warning")

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin = cur.fetchone()
        cur.close()
        conn.close()

        if admin and check_password_hash(admin["password"], password):
            session["admin_username"] = username
            return redirect(url_for("admin.dashboard"))

        if username == DEFAULT_ADMIN["username"] and password == DEFAULT_ADMIN["password"]:
            session["admin_username"] = username
            return redirect(url_for("admin.dashboard"))

        flash("Invalid username or password", "danger")
        return redirect(url_for("admin.login"))

    return render_template("admin/adminLogin.html")

@admin_bp.route("/chatbot", methods=["POST"])
def chatbot():
    data = request.get_json()
    user_msg = data.get("message", "").strip()

    if not user_msg:
        return jsonify({"reply": "Please enter a message."})

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are DAN, the AI assistant of AspireMatch.\n"
                        "Return JSON ONLY when appropriate.\n"
                        "Supported actions: query, report, help, document."
                    )
                },
                {"role": "user", "content": user_msg}
            ],
            temperature=0.4
        )

        reply_text = response.choices[0].message.content.strip()

        # Try JSON parsing
        try:
            parsed = json.loads(reply_text)
            action = parsed.get("action")

            if action == "query":
                return jsonify({"reply": run_sql(parsed.get("sql", ""))})

            if action == "report":
                return jsonify({"reply": generate_report(parsed)})

            if action == "help":
                return jsonify({"reply": "\n".join(parsed.get("steps", []))})

            if action == "document":
                return jsonify({
                    "reply": f"📄 {parsed.get('title','')}\n\n{parsed.get('body','')}"
                })

        except json.JSONDecodeError:
            pass  # normal text response

        return jsonify({"reply": reply_text})

    except Exception as e:
        return jsonify({"reply": f"⚠️ AI unavailable: {str(e)}"})

@admin_bp.route("/dashboard", methods=["GET", "POST"]) 
def dashboard():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))
    
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT firstname FROM admin WHERE username = %s;", (session["admin_username"],))
    admin_row = cur.fetchone()
    firstname = admin_row[0] if admin_row else "Admin"

    cur.execute("SELECT DISTINCT EXTRACT(YEAR FROM created_at)::int FROM student ORDER BY 1 DESC;")
    available_years = [row[0] for row in cur.fetchall()]

    selected_year = request.args.get("year", type=int)

    if not selected_year:
        selected_year = datetime.now().year  

    cur.execute("""
        SELECT COUNT(*) FROM student
        WHERE EXTRACT(YEAR FROM created_at) = %s;
    """, (selected_year,))
    total_students = cur.fetchone()[0]

    pending_students = 0
    active_admins = 0

    cur.close()
    conn.close()

    return render_template(
        "admin/dashboard.html",
        admin_username=session["admin_username"],
        firstname=firstname,
        total_students=total_students,
        pending_students=pending_students,
        active_admins=active_admins,
        year=selected_year,
        available_years=available_years
    )

@admin_bp.route("/addAdmin", methods=["GET", "POST"])
def addAdmin():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    message = None
    category = None

    if request.method == "POST":
        firstname = request.form["first_name"]
        middlename = request.form["middle_name"]
        lastname = request.form["last_name"]
        username = request.form["user_name"]
        email = request.form["email"]
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

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO admin (firstname, middlename, lastname, username, email, password)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (firstname, middlename, lastname, username, email, hashed_pw))

            cur.execute("""
                INSERT INTO admin_logs (admin_username, action)
                VALUES (%s, %s)
            """, (session["admin_username"], f"Added new admin '{username}'"))

            conn.commit()
            cur.close()
            conn.close()

            message = "Administrator added successfully!"
            category = "success"

        except psycopg2.Error as e:
            if "unique constraint" in str(e).lower():
                message = "Username already exists!"
                category = "danger"
            else:
                message = f"Error: {str(e)}"
                category = "danger"

    admins = []
    if session["admin_username"] == "hk":
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, firstname, middlename, lastname, username, email, created_at FROM admin")
        admins = cur.fetchall()
        cur.close()
        conn.close()

    return render_template(
        "admin/addAdmin.html",
        admin_username=session["admin_username"],
        message=message,
        category=category,
        admins=admins
    )

@admin_bp.route("/addParticipant", methods=["POST"])
def addParticipant():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    fullname = request.form["full_name"]
    exam_id = request.form["exam_id"]
    gender = request.form["gender"]
    email = request.form["email"]

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT id FROM admin WHERE username = %s", (session["admin_username"],))
        admin_row = cur.fetchone()
        admin_id = admin_row[0] if admin_row else None

        cur.execute("SELECT * FROM student WHERE exam_id = %s OR email = %s", (exam_id, email))
        existing = cur.fetchone()

        if existing:
            cur.close()
            conn.close()
            flash("❌ Examination ID or Email already exists!", "danger")
            return redirect(url_for("admin.dashboard"))

        cur.execute("""
            INSERT INTO student (fullname, exam_id, gender, email, added_by)
            VALUES (%s, %s, %s, %s, %s)
        """, (fullname, exam_id, gender, email, admin_id))

        conn.commit()
        cur.close()
        conn.close()

        flash("✅ Participant added successfully!", "success")
        return redirect(url_for("admin.dashboard"))

    except Exception as e:
        flash(f"⚠️ Error: {str(e)}", "danger")
        return redirect(url_for("admin.dashboard"))

@admin_bp.route("/upload", methods=["POST"])
def upload():
    # 🔐 Auth check
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    # 📁 File existence check
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

    try:
        # 📊 Read Excel directly from memory (NO save)
        df = pd.read_excel(file, dtype=str)

        # Normalize headers
        df.columns = df.columns.str.lower().str.strip()

        required_cols = {"fullname", "exam_id", "gender", "email"}
        if not required_cols.issubset(df.columns):
            return render_template(
                "dashboard.html",
                error="Excel must contain columns: fullname, exam_id, gender, email"
            )

        conn = get_db_connection()
        cur = conn.cursor()

        inserted = 0
        skipped = 0

        for _, row in df.iterrows():
            fullname = (row.get("fullname") or "").strip()
            exam_id = (row.get("exam_id") or "").strip()
            gender = (row.get("gender") or "").strip()
            email = (row.get("email") or "").strip()

            # 🚫 Skip incomplete rows
            if not fullname or not exam_id or not email:
                skipped += 1
                continue

            # 🚫 Prevent duplicate exam_id
            cur.execute(
                "SELECT 1 FROM student WHERE exam_id = %s",
                (exam_id,)
            )
            if cur.fetchone():
                skipped += 1
                continue

            # ✅ Insert student
            cur.execute(
                """
                INSERT INTO student (fullname, exam_id, gender, email)
                VALUES (%s, %s, %s, %s)
                """,
                (fullname, exam_id, gender, email)
            )
            inserted += 1

        conn.commit()
        cur.close()
        conn.close()

        return render_template(
            "dashboard.html",
            success=f"Upload complete! Inserted: {inserted}, Skipped: {skipped}"
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
        AND (%s = '' OR s.fullname ILIKE %s)
        ORDER BY s.fullname ASC; 
    """, (selected_year, search_query, f"%{search_query}%"))
    
    raw_students = cur.fetchall()

    students = []
    for row in raw_students:
        exam_id, fullname, preferred_program, *pairs = row

        match_status = "—"

        if any(pairs):  
            counts = Counter(pairs)
            top_three = [letter for letter, _ in counts.most_common(3)]

            if preferred_program and top_three:
                if any(letter in preferred_program_map.get(preferred_program, []) for letter in top_three):
                    match_status = "✔️ Match"
                else:
                    match_status = "❌ Not Match"

        students.append((exam_id, fullname, preferred_program, match_status))

    cur.close()
    conn.close()

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

    cur.execute("""
        SELECT s.exam_id, s.fullname, s.created_at, sa.preferred_program,
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

    created_at = row[2]
    year = created_at.year

    if not row:
        flash("Student data not found.")
        return redirect(url_for("admin.dashboard"))

    student_results = {
        "exam_id": row[0],
        "fullname": row[1],
        "created_at": row[2],
        "preferred_program": row[3],
        "answers": [row[i] for i in range(4, 90)]
    }

    answers_clean = [ans for ans in student_results["answers"] if ans]
    letter_counts = Counter(answers_clean)
    top_letters = [letter for letter, _ in letter_counts.most_common(3)]

    preferred = student_results["preferred_program"]

    if not preferred and not answers_clean:
        match_status = "Not Yet Answer"
    elif preferred in preferred_program_map and any(letter in preferred_program_map[preferred] for letter in top_letters):
        match_status = "Match"
    else:
        match_status = "Not Match"

    return render_template(
        "admin/adminSurveyResult.html",
        admin_username=session["admin_username"],
        student_results=student_results,
        top_letters=top_letters,
        letter_descriptions=letter_descriptions,
        match_status=match_status,
        year=year
    )

@admin_bp.route("/generateMatchExplanation/<exam_id>")
def generateMatchExplanation(exam_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT s.fullname, sa.preferred_program,
               ARRAY[
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
               ] AS answers
        FROM student s
        LEFT JOIN student_survey_answer sa ON s.exam_id = sa.exam_id
        WHERE s.exam_id = %s
    """, (exam_id,))

    row = cur.fetchone()
    conn.close()

    fullname = row[0]
    preferred_program = row[1]
    answers = [a for a in row[2] if a]

    counts = Counter(answers)
    top_letters = [letter for letter, _ in counts.most_common(3)]

   # Prepare short letter meanings
    letter_meanings = "\n".join(
        [f"{ltr}: {short_letter_descriptions.get(ltr, 'No description')}" for ltr in top_letters]
    )

    letters_str = ", ".join(top_letters)

    prompt = f"""
    You are an educational guidance AI.
    The student's name is {fullname}.
    Their top career letters are: {letters_str}.

    Meaning of each letter:
    {letter_meanings}

    Their preferred program is: {preferred_program}.

    Create a clear, organized, and easy-to-read explanation with the following numbered sections. 
    Make each section separate with blank lines. 
    Follow exactly this structure:

    1. Career Letter Explanation
    Explain the meaning of each top letter using only the short meanings provided and add short explaination of that letter.

    2. Strengths
    List strengths based on the student's top letters.
    Use bullet points with the symbol •

    3. Weaknesses
    List possible weaknesses based on the letters.
    Use bullet points with the symbol •

    4. Personalized Career Advice
    Provide supportive and friendly guidance based on the student's top letters and preferred program.

    5. Recommended Courses or Subjects
    Suggest helpful subjects or courses based on the student's letters and interests.

    VERY IMPORTANT RULES:
    - Do NOT use asterisks
    - Do NOT use hashtags
    - Do NOT apply markdown formatting
    - Bullets must only use: •
    - Keep the tone friendly, simple, and encouraging
    - Maintain blank lines between sections
    """

    try:
        ai_response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}]
        )
        explanation = ai_response.choices[0].message.content
    except Exception as e:
        explanation = f"Error generating explanation: {str(e)}"

    return jsonify({"explanation": explanation})

@admin_bp.route('/download_result/<exam_id>')
def download_result(exam_id):
    if not exam_id:
        flash("Invalid request.")
        return redirect(url_for('admin.dashboard'))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT s.exam_id, s.fullname, s.created_at, sa.preferred_program,
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
        WHERE s.id = %s;
    """, (exam_id,))

    row = cur.fetchone()
    conn.close()

    created_at = row[2]
    year = created_at.year

    if not row:
        return "Survey results not found", 404

    student_data = {
        "exam_id": row[0],
        "fullname": row[1],
        "created_at": row[2],
        "preferred_program": row[3],
        "answers": [row[i] for i in range(4, 90)]
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
        letter_descriptions=letter_descriptions,
        year=year,
        cpsu_logo_base64=cpsu_logo,
        bagong_logo_base64=bagong_logo,
        safe_logo_base64=safe_logo
    )

    pdf_io = BytesIO()
    HTML(string=html, base_url=current_app.root_path).write_pdf(pdf_io)
    pdf_io.seek(0)

    filename = f"Survey_Result_{student_data['exam_id']}.pdf"

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
    cur = conn.cursor()

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
            s.exam_id, 
            s.fullname,
            COALESCE(f.father_income, 0) + COALESCE(f.mother_income, 0) AS total_income
        FROM student s
        LEFT JOIN family_background f 
            ON f.student_id = s.id
        WHERE EXTRACT(YEAR FROM s.created_at) = %s
        AND (%s = '' OR s.fullname ILIKE %s)
        -- Sorting handled in Python instead of SQL
        ORDER BY s.fullname ASC;
    """, (selected_year, search_query, f"%{search_query}%"))

    students = cur.fetchall()

    sort = request.args.get("sort", "default")

    classified_students = []
    for exam_id, fullname, total_income in students:
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

        classified_students.append((exam_id, fullname, income_display, category))

    def sorting_key(item):
        exam_id, fullname, income, category = item

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
    cur = conn.cursor()

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT 
            s.id AS id,
            s.fullname, s.gender, s.email,
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
        info=info,
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
            s.fullname, s.gender, s.email,
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
    # ---------- DB FETCH ----------
    conn = get_db_connection()
    cur = conn.cursor()

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
    cur.close()
    conn.close()

    if not row:
        return jsonify({"error": "Student not found"}), 404

    fullname = row[0]
    preferred_program = row[1]
    letters = [l for l in row[2:] if l]  # Remove None values

    if not letters:
        return jsonify({"error": "Student has no survey answers"}), 400

    # ---------- PROCESS LETTERS ----------
    counts = Counter(letters)
    top_three = [l for l, _ in counts.most_common(3)]
    top_three_descriptions = [short_letter_descriptions.get(l, "Unknown") for l in top_three]
    all_letter_descriptions = [short_letter_descriptions.get(l, "Unknown") for l in letters]
    required_letters = preferred_program_map.get(preferred_program, [])
    required_descriptions = [short_letter_descriptions.get(l, "Unknown") for l in required_letters]

    # ---------- AI PROMPT ----------
    prompt = f"""
    You are an educational guidance AI.

    Student: {fullname}
    Preferred Program: {preferred_program}

    Program Required Letters: {required_letters}
    Program Required Descriptions: {required_descriptions}

    Student Top 3 Letters: {top_three}
    Top 3 Descriptions: {top_three_descriptions}

    All 86 Answers (Letters): {letters}
    All 86 Answers (Descriptions): {all_letter_descriptions}

    Use ONLY the descriptions from short_letter_descriptions.
    Do NOT use Holland RIASEC.
    Do NOT invent traits. Stick to the given descriptions.

    For mismatch explanation:
    - Compare the preferred program's required letters + descriptions
    - With the student's top 3 letters + descriptions
    - Explain clearly why they align or do not align

    Return JSON ONLY:

    {{
    "questions": [
        "question1",
        "question2",
        "question3",
        "question4",
        "question5",
        "question6"
    ],
    "mismatch_reason": "Explain mismatch based strictly on required letters vs top letters and their descriptions.",
    "talking_points": [
        "point1",
        "point2",
        "point3"
    ]
    }}
    """

    # ---------- OPENAI CALL ----------
    
    print("DEBUG OPENAI KEY:", os.getenv("OPENAI_API_KEY"))

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    ai = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt
    )

    try:
        content = ai.output[0].content[0].text
        data = json.loads(content)
    except:
        return jsonify({"error": "AI formatting error"}), 500

    # ---------- RETURN CLEAN JSON ----------
    return jsonify({
        "questions": data.get("questions", []),
        "mismatch_reason": data.get("mismatch_reason", ""),
        "talking_points": data.get("talking_points", [])
    })

PER_PAGE = 10

@admin_bp.route("/interviewList")
def interviewList():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    conn = get_db_connection()
    cur = conn.cursor()

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
        AND (%s = '' OR s.fullname ILIKE %s)
        ORDER BY s.fullname ASC;
    """, (selected_year, search_query, f"%{search_query}%"))

    raw_students = cur.fetchall()
    cur.close()
    conn.close()

    students = []
    for row in raw_students:
        student_id, exam_id, fullname, preferred_program, *pairs_and_sched = row
        pairs = pairs_and_sched[:-3]
        schedule_date, start_time, end_time = pairs_and_sched[-3:]

        match_status = "Not Yet Answer"
        top_three = []

        if any(pairs):
            counts = Counter(pairs)
            top_three = [letter for letter, _ in counts.most_common(3)]

            if preferred_program and top_three:
                if any(letter in preferred_program_map.get(preferred_program, []) for letter in top_three):
                    match_status = "Match"
                else:
                    match_status = "Not Match"

        if match_status == "Not Match":
            if schedule_date:
                schedule_str = f"{schedule_date.strftime('%Y-%m-%d')} ({start_time.strftime('%I:%M %p')} - {end_time.strftime('%I:%M %p')})"
            else:
                schedule_str = None

            students.append((student_id, exam_id, fullname, schedule_str))

    total_students = len(students)
    total_pages = ceil(total_students / PER_PAGE)
    start = (page - 1) * PER_PAGE
    end = start + PER_PAGE
    students_paginated = students[start:end]

    return render_template(
        "admin/interviewList.html",
        admin_username=session["admin_username"],
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
        cur.execute("SELECT 1 FROM schedules WHERE schedule_date = %s", (schedule_date,))
        if cur.fetchone():
            return jsonify({
                "status": "error",
                "error": "A schedule already exists for this date."
            }), 400

        cur.execute("""
            INSERT INTO schedules (schedule_date, start_time, end_time, slot_count, admin_username)
            VALUES (%s, %s, %s, %s, %s)
        """, (schedule_date, start_time, end_time, slot_count, admin_username))
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
        conn.close()

@admin_bp.route("/visualization")
def visualization():
    if "admin_username" not in session:
        return redirect(url_for("admin.login"))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT DISTINCT EXTRACT(YEAR FROM s.created_at)::int
        FROM student s
        ORDER BY 1 ASC;
    """)
    available_years = [row[0] for row in cur.fetchall()]

    current_year = datetime.now().year
    selected_year = request.args.get("year", str(current_year))
    selected_gender = request.args.get("gender", "All")

    def fetch_data_for_year(year=None, gender=None):
        params = []
        filters = []

        if year is not None:
            filters.append("EXTRACT(YEAR FROM s.created_at) = %s")
            params.append(year)

        if gender and gender != "All":
            filters.append("LOWER(s.gender) = LOWER(%s)")
            params.append(gender)

        where_clause = "WHERE " + " AND ".join(filters) if filters else ""

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
            LIMIT 3;
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
        available_years=available_years,
        year=str(selected_year),
        gender=str(selected_gender),
        all_years_data=all_years_data
    )

@admin_bp.route("/generate_ai_visualization_insights", methods=["POST"])
def generate_ai_visualization_insights():
    req = request.get_json()
    data = req.get("data", [])

    prompt = f"""
    You are an educational analytics AI.
    Analyze the following dataset from student survey visualizations:

    {data}

    Generate the following insights:

    1. Yearly Trends
       - Identify increases or decreases in preferred programs.
       - Identify patterns in top letters.

    2. Gender-based Behaviors
       - Differences in choices between male and female groups.

    3. Predicted Future Program Demand
       - Which programs are likely to grow next year?
       - Which may decline?

    4. Narrative Summary of Graphs
       - Write like a report analyst summarizing the charts.

    5. Academic Planning Recommendations
       - Suggestions for schools based on student trends.

    Format the output in short paragraphs.
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
