from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, make_response, send_file, current_app
from ..db import get_db_connection
import psycopg2
import psycopg2.extras
import os
import re
from werkzeug.utils import secure_filename
from PIL import Image
from weasyprint import HTML
from io import BytesIO
import base64
import smtplib
from email.message import EmailMessage
from collections import Counter
from ..description import letter_descriptions, preferred_program_map, ai_responses, short_letter_descriptions
from math import ceil
from calendar import monthrange
import datetime
from groq import Groq
import random
import time
from datetime import datetime

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

student_bp = Blueprint('student', __name__, template_folder='../../frontend/templates/student')

UPLOAD_FOLDER = "frontend/static/uploads/students"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

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

def generate_ai_insights(top_letters, preferred_program, fullname):
    letters_str = ", ".join(top_letters)

    # Convert letters to short descriptions
    letter_meanings = ", ".join(
        [f"{l} ({short_letter_descriptions.get(l, 'Unknown')})" for l in top_letters]
    )

    prompt = f"""
    You are an educational guidance AI.
    The student's name is {fullname}.
    Their top career letters are: {letters_str}.

    The short meaning of each letter:
    {letter_meanings}

    Their preferred program is: {preferred_program}.

    Create a clean, aesthetic, and easy-to-read explanation with the following sections ONLY:

    Career Letter Explanation 
    - Explain each letter using the short meanings only.

    Strengths
    - List strengths based on the letters.
    - Use bullet points with the symbol "•"

    Weaknesses
    - List possible weaknesses based on the letters.
    - Use bullet points with the symbol "•"

    Personalized Career Advice
    - Provide friendly guidance.
    - two sentence only

    Recommended Courses or Subjects
    - Provide study recommendations about the top letter meaning.
    - Their top career letters are: {letter_meanings}

    VERY IMPORTANT RULES:
    - Do NOT use asterisks (*)
    - Do NOT use hashtags (#)
    - Do NOT format as markdown
    - Use simple bullet points: "•"
    - Keep tone friendly, simple, and encouraging
    """

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an educational guidance AI. "
                    "You MUST return ONLY plain text. "
                    "Do NOT use asterisks (*), hashtags (#), or markdown formatting. "
                    "Use only • for bullet points and plain headings without extra symbols."
                )
            },
            {"role": "user", "content": prompt}
        ],
        temperature=0.3,
        max_tokens=700
    )

    return response.choices[0].message.content

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

    # Clean extra line breaks
    formatted = re.sub(r"\n{3,}", "\n\n", text).strip()

    for title in sections:
        formatted = re.sub(
            rf"\b{re.escape(title)}\b",
            f"<div class='ai-section-title'>{title}</div>",
            formatted,
            flags=re.IGNORECASE
        )

    # Convert line breaks to <br>
    formatted = formatted.replace("\n", "<br>")

    return formatted

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    msg = EmailMessage()
    msg["Subject"] = "Your AspireMatch Login OTP"
    msg["From"] = "aspirematch2@gmail.com"
    msg["To"] = email
    msg.set_content(f"""
Your One-Time Password (OTP) is:

{otp}

This code will expire in 5 minutes.
""")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login("aspirematch2@gmail.com", "bvti ptud ebch pmee")
        server.send_message(msg)

@student_bp.route("/test-db")
def test_db():
    conn = get_db_connection()
    return "DB CONNECTED"

@student_bp.route("/get_letter_description/<letter>")
def get_letter_description(letter):
    description = letter_descriptions.get(letter, "No description available.")
    return jsonify({ "description": description })

@student_bp.route("/")
def login_page():
    return render_template("student/studentLogin.html")

@student_bp.route("/login", methods=["GET", "POST"])
def studentlogin():
    error = None
    exam_error = False
    email_error = False

    if request.method == "POST":
        exam_id = request.form["exam_id"]
        email = request.form["email"]

        conn = get_db_connection()
        cur = conn.cursor()

        # 1️⃣ Check if exam ID exists
        cur.execute(
            "SELECT * FROM student WHERE exam_id = %s",
            (exam_id,)
        )
        student_by_exam = cur.fetchone()

        if not student_by_exam:
            exam_error = True
            error = "Invalid Examination ID"

        else:
            otp = generate_otp()

            session["otp"] = otp
            session["otp_exam_id"] = exam_id
            session["otp_email"] = email
            session["otp_time"] = time.time()

            send_otp_email(email, otp)

            cur.close()
            conn.close()

            return redirect(url_for("student.verify"))

        cur.close()
        conn.close()

        return render_template(
            "student/studentLogin.html",
            error=error,
            exam_error=exam_error,
            email_error=email_error,
            exam_id=exam_id,
            email=email
        )

    return render_template("student/studentLogin.html")

@student_bp.route("/verify", methods=["GET", "POST"])
def verify():
    error = None
    success = None

    if request.method == "POST":

        # 🔁 RESEND OTP
        if "resend" in request.form:
            last_sent = session.get("otp_time", 0)

            if time.time() - last_sent < 60:
                error = "1 minute after requesting new OTP."
            else:
                otp = generate_otp()
                session["otp"] = otp
                session["otp_time"] = time.time()

                send_otp_email(session["otp_email"], otp)
                success = "Please wait 1min before requesting a new OTP."

            return render_template(
                "student/verify.html",
                error=error,
                success=success
            )

        # ✅ VERIFY OTP
        user_otp = request.form.get("otp", "")

        if time.time() - session.get("otp_time", 0) > 300:
            error = "OTP expired. Please login again."

        elif user_otp != session.get("otp"):
            error = "Invalid OTP"

        else:
            # ✅ OTP SUCCESS → FINAL LOGIN
            exam_id = session["otp_exam_id"]

            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute(
                "SELECT id FROM student WHERE exam_id = %s",
                (exam_id,)
            )
            student = cur.fetchone()

            session["student_id"] = student[0]
            session["exam_id"] = exam_id

            # 🔍 CHECK SURVEY COMPLETION
            cur.execute("""
                SELECT preferred_program, pair1, pair2, pair3, pair4, pair5,
                       pair6, pair7, pair8, pair9, pair10,
                       pair11, pair12, pair13, pair14, pair15,
                       pair16, pair17, pair18, pair19, pair20,
                       pair21, pair22, pair23, pair24, pair25,
                       pair26, pair27, pair28, pair29, pair30,
                       pair31, pair32, pair33, pair34, pair35,
                       pair36, pair37, pair38, pair39, pair40,
                       pair41, pair42, pair43, pair44, pair45,
                       pair46, pair47, pair48, pair49, pair50,
                       pair51, pair52, pair53, pair54, pair55,
                       pair56, pair57, pair58, pair59, pair60,
                       pair61, pair62, pair63, pair64, pair65,
                       pair66, pair67, pair68, pair69, pair70,
                       pair71, pair72, pair73, pair74, pair75,
                       pair76, pair77, pair78, pair79, pair80,
                       pair81, pair82, pair83, pair84, pair85,
                       pair86
                FROM student_survey_answer
                WHERE exam_id = %s AND student_id = %s
            """, (exam_id, session["student_id"]))

            survey_row = cur.fetchone()

            # 🧹 CLEAN OTP SESSION
            session.pop("otp", None)
            session.pop("otp_email", None)
            session.pop("otp_exam_id", None)
            session.pop("otp_time", None)

            cur.close()
            conn.close()

            if survey_row and all(survey_row):
                return redirect(url_for("student.home"))
            else:
                return redirect(url_for("student.survey"))

    return render_template("student/verify.html", error=error, success=success)

@student_bp.route("/chatbot", methods=["POST"])
def chatbot():
    user_msg = request.json.get("message", "").lower()

    # ---- Rule-based replies FIRST (fast + free) ----
    if "strength" in user_msg:
        return jsonify({
            "reply": "Your strengths are tied to your top survey letters. These represent activities you naturally enjoy and can excel at. Want me to explain each letter’s strengths?"
        })

    if "weakness" in user_msg:
        return jsonify({
            "reply": "I can help identify your potential weaknesses based on your career interest profile. Tell me which letter you want to understand better."
        })

    if "course" in user_msg or "suggest" in user_msg:
        return jsonify({
            "reply": "Based on your career results, I can suggest relevant courses. What program are you interested in exploring?"
        })

    if "explain" in user_msg and "result" in user_msg:
        return jsonify({
            "reply": "Sure! Your career result shows what type of work environment fits you best. Ask me anything about your top letters!"
        })

    # ---- Groq AI fallback ----
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Your name is Dan. You are a friendly AI assistant in the AspireMatch system. "
                        "Answer clearly, simply, and in a supportive tone."
                    )
                },
                {"role": "user", "content": user_msg}
            ],
            temperature=0.4,
            max_tokens=300
        )

        reply = response.choices[0].message.content
        return jsonify({"reply": reply})

    except Exception as e:
        return jsonify({
            "reply": "Sorry, I'm having trouble responding right now. Please try again later."
        }), 500

@student_bp.route("/chatbot_receive_interest", methods=["POST"])
def chatbot_receive_interest():
    letter = request.json.get("letter")

    # pick 1 random reply
    if letter in ai_responses:
        reply = random.choice(ai_responses[letter])
    else:
        reply = "Interesting choice!"

    return {"reply": reply}

@student_bp.route("/home")
def home():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))

    student_id = session["student_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT result_unlocked, inventory_result_unlocked
        FROM notifications
        WHERE student_id = %s
        ORDER BY id DESC LIMIT 1
    """, (session["student_id"],))
    row = cur.fetchone()

    cur.execute("""
        SELECT
            MAX(CASE WHEN result_unlocked = TRUE THEN 1 ELSE 0 END),
            MAX(CASE WHEN inventory_result_unlocked = TRUE THEN 1 ELSE 0 END)
        FROM notifications
        WHERE student_id = %s
    """, (session["student_id"],))

    survey_result_unlocked, inventory_result_unlocked = cur.fetchone()

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
        LEFT JOIN student_survey_answer sa 
            ON s.exam_id = sa.exam_id
        WHERE s.id = %s;
    """, (student_id,))
    
    row = cur.fetchone()

    student_survey_answer_completed = "❌ Not Completed"
    match_status = "❌ Not Match"
    interview_status = "❌ Not Available"

    if row:
        student_results = {
            "exam_id": row[0],
            "fullname": row[1],
            "preferred_program": row[2],
            "answers": [row[i] for i in range(3, 89)]
        }

        answers_clean = [ans for ans in student_results["answers"] if ans]

        if answers_clean:
            student_survey_answer_completed = "✅ Completed"

            from collections import Counter
            letter_counts = Counter(answers_clean)
            top_letters = [letter for letter, _ in letter_counts.most_common(3)]

            preferred = student_results["preferred_program"]

            cur.execute("""
                SELECT category_letter
                FROM program
                WHERE program_name = %s
            """, (preferred,))
            program_row = cur.fetchone()

            if program_row:
                program_letters = [l.strip() for l in program_row[0].split(",")]
                if any(letter in program_letters for letter in top_letters):
                    match_status = "✅ Match"
                    interview_status = "Don't need for interview"
                else:
                    match_status = "❌ Not Match"

            # If student is NOT matched, check if they already have a schedule
            if match_status == "❌ Not Match":
                cur.execute("""
                    SELECT sc.schedule_date, sc.start_time, sc.end_time
                    FROM student_schedules ss
                    JOIN schedules sc ON ss.schedule_id = sc.id
                    WHERE ss.student_id = %s;
                """, (student_id,))
                picked = cur.fetchone()

                if picked:
                    schedule_date, start_time, end_time = picked
                    from datetime import datetime
                    start_12 = datetime.strptime(str(start_time), "%H:%M:%S").strftime("%I:%M %p")
                    end_12 = datetime.strptime(str(end_time), "%H:%M:%S").strftime("%I:%M %p")
                    interview_status = f"{schedule_date} ({start_12} - {end_12})"
                else:
                    interview_status = "add_date"

    cur.execute("""
        SELECT COUNT(*) 
        FROM personal_descriptions 
        WHERE student_id = %s;
    """, (student_id,))
    inventory_count = cur.fetchone()[0]

    if inventory_count > 0:
        inventory_status = "completed"
    else:
        inventory_status = "not_completed"

    conn.close()

    return render_template(
        "student/home.html",
        student_results=student_results,
        student_survey_answer_completed=student_survey_answer_completed,
        match_status=match_status,
        interview_status=interview_status,
        inventory_status=inventory_status,
        survey_result_unlocked=survey_result_unlocked,
        inventory_result_unlocked=inventory_result_unlocked
    )

@student_bp.route("/choose_schedule")
def choose_schedule():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))

    student_id = session["student_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT result_unlocked
        FROM notifications
        WHERE student_id = %s
        ORDER BY id DESC LIMIT 1
    """, (session["student_id"],))
    row = cur.fetchone()

    cur.execute("""
        SELECT
            MAX(CASE WHEN result_unlocked = TRUE THEN 1 ELSE 0 END),
            MAX(CASE WHEN inventory_result_unlocked = TRUE THEN 1 ELSE 0 END)
        FROM notifications
        WHERE student_id = %s
    """, (session["student_id"],))

    survey_result_unlocked, inventory_result_unlocked = cur.fetchone()

    cur.close()
    conn.close()

    return render_template("student/choose_schedule.html",
        survey_result_unlocked=survey_result_unlocked)


@student_bp.route("/get_schedules")
def get_schedules():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, schedule_date, start_time, end_time, slot_count
        FROM schedules
        WHERE slot_count > 0
        ORDER BY schedule_date ASC
    """)
    rows = cur.fetchall()

    schedules = []
    for r in rows:
        schedules.append({
            "id": r[0],
            "date": r[1].strftime("%Y-%m-%d"),
            "start_time": str(r[2]),
            "end_time": str(r[3]),
            "slots": r[4]
        })

    cur.close()
    conn.close()
    return jsonify(schedules)


@student_bp.route("/save_student_schedule", methods=["POST"])
def save_student_schedule():
    data = request.json
    schedule_id = data.get("schedule_id")
    student_id = session.get("student_id")

    if not student_id or not schedule_id:
        return jsonify({"success": False, "message": "Missing data"})

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT 1 FROM student_schedules WHERE student_id = %s AND schedule_id = %s
    """, (student_id, schedule_id))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({"success": False, "message": "Already selected"})

    cur.execute("""
        INSERT INTO student_schedules (student_id, schedule_id, created_at)
        VALUES (%s, %s, NOW())
    """, (student_id, schedule_id))

    cur.execute("""
        UPDATE schedules SET slot_count = slot_count - 1 WHERE id = %s
    """, (schedule_id,))

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"success": True, "message": "Schedule saved successfully"})

@student_bp.route("/survey")
def survey():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))
    
    student_id = session["student_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            s.fullname, s.gender, s.email
        FROM student s
        WHERE s.id = %s
    """, (student_id,))

    info = cur.fetchone()
                
    return render_template("student/survey.html", info=info)

@student_bp.route("/surveyForm")
def surveyForm():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))
    student_id = session["student_id"]
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT campus
        FROM student
        WHERE id = %s
    """, (student_id,))
    student_campus = cur.fetchone()[0]
    cur.execute("""
        SELECT program_name
        FROM program
        WHERE campus = %s AND is_active = TRUE
        ORDER BY program_name
    """, (student_campus,))
    programs = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "student/surveyForm.html",
        programs=programs
    )

@student_bp.route("/save_answer", methods=["POST"])
def save_answer():
    if "exam_id" not in session or "student_id" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 403

    data = request.json
    pair_number = data.get("pair_number")
    selected_option = data.get("selected_option")

    TOTAL_PAIRS = 86

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        column_name = f"pair{pair_number + 1}"

        cur.execute(
            "SELECT id FROM student_survey_answer WHERE exam_id = %s AND student_id = %s",
            (session["exam_id"], session["student_id"])
        )
        row = cur.fetchone()

        if row:
            cur.execute(
                f"UPDATE student_survey_answer SET {column_name} = %s WHERE exam_id = %s AND student_id = %s",
                (selected_option, session["exam_id"], session["student_id"])
            )
        else:
            cur.execute(
                f"INSERT INTO student_survey_answer (exam_id, student_id, {column_name}) VALUES (%s, %s, %s)",
                (session["exam_id"], session["student_id"], selected_option)
            )

        # ✅ IF LAST QUESTION → INSERT NOTIFICATION
        if pair_number == TOTAL_PAIRS - 1:
            cur.execute("""
                SELECT 1 FROM notifications
                WHERE student_id = %s AND exam_id = %s
                  AND message = %s
            """, (
                session["student_id"],
                session["exam_id"],
                "Career Interest Survey Completed!"
            ))

            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO notifications (student_id, exam_id, message, is_read)
                    VALUES (%s, %s, %s, FALSE)
                """, (
                    session["student_id"],
                    session["exam_id"],
                    "Career Interest Survey Completed!"
                ))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"status": "success", "message": "Answer saved!"})

    except Exception as e:
        print("Error saving answer:", e)
        return jsonify({"status": "error", "message": "Failed to save answer"}), 500

@student_bp.route("/save_preferred_program", methods=["POST"])
def save_preferred_program():
    if "exam_id" not in session or "student_id" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 403

    preferred_program = request.form.get("preferredProgram")

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT id FROM student_survey_answer WHERE exam_id = %s AND student_id = %s",
            (session["exam_id"], session["student_id"])
        )
        row = cur.fetchone()

        if row:
            cur.execute(
                "UPDATE student_survey_answer SET preferred_program = %s WHERE exam_id = %s AND student_id = %s",
                (preferred_program, session["exam_id"], session["student_id"])
            )
        else:
            cur.execute(
                "INSERT INTO student_survey_answer (exam_id, student_id, preferred_program) VALUES (%s, %s, %s)",
                (session["exam_id"], session["student_id"], preferred_program)
            )

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"status": "success", "message": "Preferred program saved!"})

    except Exception as e:
        print("Error saving preferred program:", e)
        return jsonify({"status": "error", "message": "Failed to save program"}), 500
    
@student_bp.route("/notification")
def notification():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT result_unlocked, inventory_result_unlocked
        FROM notifications
        WHERE student_id = %s
        ORDER BY id DESC LIMIT 1
    """, (session["student_id"],))
    row = cur.fetchone()

    cur.execute("""
        SELECT
            MAX(CASE WHEN result_unlocked = TRUE THEN 1 ELSE 0 END),
            MAX(CASE WHEN inventory_result_unlocked = TRUE THEN 1 ELSE 0 END)
        FROM notifications
        WHERE student_id = %s
    """, (session["student_id"],))

    survey_result_unlocked, inventory_result_unlocked = cur.fetchone()

    cur.execute("""
        SELECT message, created_at
        FROM notifications
        WHERE student_id = %s
        ORDER BY created_at DESC
    """, (session["student_id"],))
    notifications = cur.fetchall()

    cur.close()
    conn.close()

    session["survey_result_unlocked"] = survey_result_unlocked
    session["inventory_result_unlocked"] = inventory_result_unlocked

    return render_template(
        "student/notification.html",
        notifications=notifications,
        survey_result_unlocked=survey_result_unlocked,
        inventory_result_unlocked=inventory_result_unlocked
    )

@student_bp.route("/notification_read/<int:notification_id>", methods=["POST"])
def notification_read(notification_id):
    if "student_id" not in session:
        return jsonify({"status": "error"}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE notifications
        SET is_read = TRUE
        WHERE id = %s AND student_id = %s
    """, (notification_id, session["student_id"]))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"status": "success"})

@student_bp.route("/notification_count")
def notification_count():
    if "student_id" not in session:
        return jsonify({"count": 0})

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT COUNT(*) FROM notifications
        WHERE student_id = %s AND is_read = FALSE
    """, (session["student_id"],))
    count = cur.fetchone()[0]
    cur.close()
    conn.close()

    return jsonify({"count": count})

@student_bp.route("/notification_mark_all_read", methods=["POST"])
def notification_mark_all_read():
    if "student_id" not in session:
        return jsonify({"status": "error"}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE notifications
        SET is_read = TRUE
        WHERE student_id = %s AND is_read = FALSE
    """, (session["student_id"],))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"status": "success"})

@student_bp.route("/surveyResult_link_clicked")
def surveyResult_link_clicked():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE notifications
        SET result_unlocked = TRUE
        WHERE student_id = %s
    """, (session["student_id"],))
    conn.commit()
    cur.close()
    conn.close()

    session["survey_result_unlocked"] = True

    return redirect(url_for("student.surveyResult"))

@student_bp.route("/studentInventoryResult_link_clicked")
def studentInventoryResult_link_clicked():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))

    student_id = session["student_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE notifications
        SET inventory_result_unlocked = TRUE
        WHERE student_id = %s
    """, (student_id,))
    conn.commit()
    cur.close()
    conn.close()

    session["inventory_result_unlocked"] = True

    return redirect(url_for("student.studentInventoryResult"))

@student_bp.route("/surveyResult")
def surveyResult():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))

    student_id = session["student_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT result_unlocked, inventory_result_unlocked
        FROM notifications
        WHERE student_id = %s
        ORDER BY id DESC LIMIT 1
    """, (session["student_id"],))
    row = cur.fetchone()
    
    cur.execute("""
        SELECT
            MAX(CASE WHEN result_unlocked = TRUE THEN 1 ELSE 0 END),
            MAX(CASE WHEN inventory_result_unlocked = TRUE THEN 1 ELSE 0 END)
        FROM notifications
        WHERE student_id = %s
    """, (session["student_id"],))

    survey_result_unlocked, inventory_result_unlocked = cur.fetchone()

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
        LEFT JOIN student_survey_answer sa 
            ON s.exam_id = sa.exam_id
        WHERE s.id = %s;
    """, (student_id,))
    
    row = cur.fetchone()

    created_at = row[2]

    start_year = created_at.year
    end_year = start_year + 1
    year = f"{start_year}-{end_year}"

    if not row:
        return "No survey results found."

    student_results = {
        "exam_id": row[0],
        "fullname": row[1],
        "created_at": row[2],
        "campus": row[3],
        "photo": row[4],
        "preferred_program": row[5],
        "ai_explanation": row[6],
        "answers": [row[i] for i in range(7, 93)]
    }

    answers_clean = student_results["answers"]
    preferred = student_results["preferred_program"]

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
        "student/surveyResult.html",
        year=year,
        student_results=student_results,
        student_campus=student_results["campus"],
        top_letters=top_letters,
        letter_descriptions=letter_descriptions,
        match_status=match_status,
        survey_result_unlocked=survey_result_unlocked,
        inventory_result_unlocked=inventory_result_unlocked
    )

@student_bp.route("/generate-ai-explanation", methods=["POST"])
def generate_ai_explanation():
    if "student_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    top_letters = data.get("top_letters", [])
    preferred_program = data.get("preferred_program", "")
    fullname = data.get("fullname", "")

    explanation = generate_ai_insights(
        top_letters,
        preferred_program,
        fullname
    )

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE student_survey_answer
        SET ai_explanation = %s
        WHERE exam_id = (
            SELECT exam_id FROM student WHERE id = %s
        )
    """, (explanation, session["student_id"]))

    conn.commit()
    conn.close()

    return jsonify({"explanation": explanation})

@student_bp.route('/download_pdf/<int:student_id>')
def download_pdf(student_id):
    if "student_id" not in session or session["student_id"] != student_id:
        return redirect(url_for("login_page"))

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
        WHERE s.id = %s;
    """, (student_id,))

    row = cur.fetchone()

    created_at = row[2]

    start_year = created_at.year
    end_year = start_year + 1
    year = f"{start_year}-{end_year}"

    if not row:
        return "Survey results not found", 404

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

    answers_clean = student_data["answers"]
    preferred = student_data["preferred_program"]  # <- ALWAYS define it

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

    student_photo_base64 = None

    student_photo_base64 = student_photo_to_base64(student_data.get("photo"))

    cpsu_logo = image_to_base64("cpsulogo.png")
    bagong_logo = image_to_base64("bagong-pilipinas-logo.png")
    safe_logo = image_to_base64("logo.png")

    html = render_template(
        "student/surveyResultPDF.html",
        year=year,
        student_data=student_data,
        student_campus=student_data["campus"],
        top_letters=top_letters,
        match_status=match_status,
        letter_descriptions=letter_descriptions,
        cpsu_logo_base64=cpsu_logo,
        bagong_logo_base64=bagong_logo,
        safe_logo_base64=safe_logo,
        student_photo_base64=student_photo_base64
    )

    pdf_io = BytesIO()
    HTML(string=html, base_url=current_app.root_path).write_pdf(pdf_io)
    pdf_io.seek(0)

    filename = f"Survey_Result_{student_data['exam_id']}.pdf"

    print("PHOTO FILE:", student_data["photo"])
    print("PHOTO BASE64:", bool(student_photo_base64))

    return send_file(
        pdf_io,
        mimetype="application/pdf",
        download_name=filename,
        as_attachment=True
    )

@student_bp.route("/studentInventory")
def studentInventory():
    if "exam_id" not in session or "student_id" not in session:
        return redirect(url_for("student.login_page"))

    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch all programs for dropdown
    cur.execute("SELECT program_name FROM program ORDER BY program_name")
    programs = [row[0] for row in cur.fetchall()]

    cur.close()
    conn.close()

    return render_template("student/studentInventory.html", programs=programs)


@student_bp.route("/student/save_course", methods=["POST"])
def save_course():
    if "exam_id" not in session or "student_id" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401

    course_name = request.form.get("course_name")
    exam_id = session["exam_id"]
    student_id = session["student_id"]

    if not course_name:
        return jsonify({"status": "error", "message": "Course is required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    # Check if course already exists for this exam_id
    cur.execute("SELECT id FROM course WHERE exam_id = %s AND student_id = %s", (exam_id, student_id))
    existing = cur.fetchone()

    if existing:
        # Update existing course
        cur.execute("""
            UPDATE course
            SET course_name = %s, created_at = %s
            WHERE exam_id = %s AND student_id = %s
        """, (course_name, datetime.now(), exam_id, student_id))
    else:
        # Insert new course
        cur.execute("""
            INSERT INTO course (exam_id, student_id, course_name, created_at)
            VALUES (%s, %s, %s, %s)
        """, (exam_id, student_id, course_name, datetime.now()))

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"status": "success", "message": "Course saved successfully"})

@student_bp.route("/studentInventoryForm", methods=["GET", "POST"])
def studentInventoryForm():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))

    student_id = session["student_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        
        nickname = request.form.get("nickname")
        present_address = request.form.get("present_address")
        provincial_address = request.form.get("provincial_address")
        date_of_birth = request.form.get("date_of_birth")
        place_of_birth = request.form.get("place_of_birth")
        age = request.form.get("age")
        birth_order = request.form.get("birth_order")
        siblings_count = request.form.get("siblings_count")
        civil_status = request.form.get("civil_status")
        religion = request.form.get("religion")
        nationality = request.form.get("nationality")
        home_phone = request.form.get("home_phone")
        mobile_no = request.form.get("mobile_no")
        email = request.form.get("email")
        weight = request.form.get("weight")
        height = request.form.get("height")
        blood_type = request.form.get("blood_type")
        hobbies = request.form.get("hobbies")
        talents = request.form.get("talents")
        emergency_name = request.form.get("emergency_name")
        emergency_relationship = request.form.get("emergency_relationship")
        emergency_address = request.form.get("emergency_address")
        emergency_contact = request.form.get("emergency_contact")

        father_name = request.form.get("father_name")
        father_age = request.form.get("father_age")
        father_education = request.form.get("father_education")
        father_occupation = request.form.get("father_occupation")
        father_income = request.form.get("father_income")
        father_contact = request.form.get("father_contact")

        mother_name = request.form.get("mother_name")
        mother_age = request.form.get("mother_age")
        mother_education = request.form.get("mother_education")
        mother_occupation = request.form.get("mother_occupation")
        mother_income = request.form.get("mother_income")
        mother_contact = request.form.get("mother_contact")

        married_living_together = bool(request.form.get("married_living_together"))
        living_not_married = bool(request.form.get("living_not_married"))
        legally_separated = bool(request.form.get("legally_separated"))
        mother_widow = bool(request.form.get("mother_widow"))
        father_widower = bool(request.form.get("father_widower"))
        separated = bool(request.form.get("separated"))
        father_another_family = bool(request.form.get("father_another_family"))
        mother_another_family = bool(request.form.get("mother_another_family"))

        elementary_school_name = request.form.get("elementary_school_name")
        elementary_year_graduated = request.form.get("elementary_year_graduated")
        elementary_awards = request.form.get("elementary_awards")

        junior_high_school_name = request.form.get("junior_high_school_name")
        junior_high_year_graduated = request.form.get("junior_high_year_graduated")
        junior_high_awards = request.form.get("junior_high_awards")

        senior_high_school_name = request.form.get("senior_high_school_name")
        senior_high_year_graduated = request.form.get("senior_high_year_graduated")
        senior_high_awards = request.form.get("senior_high_awards")
        senior_high_track = request.form.get("senior_high_track")
        senior_high_strand = request.form.get("senior_high_strand")

        subject_interested = request.form.get("subject_interested")
        org_membership = request.form.get("org_membership")
        study_finance = request.form.get("study_finance")
        course_personal_choice = request.form.get("course_personal_choice")
        influenced_by = request.form.get("influenced_by")
        feeling_about_course = request.form.get("feeling_about_course")
        personal_choice = request.form.get("personal_choice")

        if not subject_interested or not course_personal_choice:
            error_message = "Please complete all required fields before proceeding."
            raise ValueError(error_message)

        if course_personal_choice == "yes":
            influenced_by = None
            feeling_about_course = None
            personal_choice = None

        enroll_reasons = request.form.getlist("enroll_reasons")
        other_reason = request.form.get("other_reason")

        reasons_str = ", ".join(enroll_reasons) if enroll_reasons else None

        other_schools = request.form.getlist("other_school")
        other_school_text = request.form.get("other_school_other")

        other_schools_str = ", ".join(other_schools) if other_schools else None

        if not other_schools_str and not other_school_text:
            flash("Please select at least one school or specify in 'Others'.", "error")
            return redirect(url_for("student.studentInventoryForm"))

        bullying = bool(request.form.get("bullying"))
        bullying_when = request.form.get("bullying_when")
        if bullying:
            bullying_bother = request.form.get("bullying_bother")
        else:
            bullying_bother = None

        suicidal_thoughts = bool(request.form.get("suicidal_thoughts"))
        suicidal_thoughts_when = request.form.get("suicidal_thoughts_when")
        if suicidal_thoughts:
            suicidal_thoughts_bother = request.form.get("suicidal_thoughts_bother")
        else:
            suicidal_thoughts_bother = None

        suicidal_attempts = bool(request.form.get("suicidal_attempts"))
        suicidal_attempts_when = request.form.get("suicidal_attempts_when")
        if suicidal_attempts:
            suicidal_attempts_bother = request.form.get("suicidal_attempts_bother")
        else:
            suicidal_attempts_bother = None

        panic_attacks = bool(request.form.get("panic_attacks"))
        panic_attacks_when = request.form.get("panic_attacks_when")
        if panic_attacks:
            panic_attacks_bother = request.form.get("panic_attacks_bother")
        else:
            panic_attacks_bother = None

        anxiety = bool(request.form.get("anxiety"))
        anxiety_when = request.form.get("anxiety_when")
        if anxiety:
            anxiety_bother = request.form.get("anxiety_bother")
        else:
            anxiety_bother = None

        depression = bool(request.form.get("depression"))
        depression_when = request.form.get("depression_when")
        if depression:
            depression_bother = request.form.get("depression_bother")
        else:
            depression_bother = None

        self_anger_issues = bool(request.form.get("self_anger_issues"))
        self_anger_issues_when = request.form.get("self_anger_issues_when")
        if self_anger_issues:
            self_anger_issues_bother = request.form.get("self_anger_issues_bother")
        else:
            self_anger_issues_bother = None

        recurring_negative_thoughts = bool(request.form.get("recurring_negative_thoughts"))
        recurring_negative_thoughts_when = request.form.get("recurring_negative_thoughts_when")
        if recurring_negative_thoughts:
            recurring_negative_thoughts_bother = request.form.get("recurring_negative_thoughts_bother")
        else:
            recurring_negative_thoughts_bother = None

        low_self_esteem = bool(request.form.get("low_self_esteem"))
        low_self_esteem_when = request.form.get("low_self_esteem_when")
        if low_self_esteem:
            low_self_esteem_bother = request.form.get("low_self_esteem_bother")
        else:
            low_self_esteem_bother = None

        poor_study_habits = bool(request.form.get("poor_study_habits"))
        poor_study_habits_when = request.form.get("poor_study_habits_when")
        if poor_study_habits:
            poor_study_habits_bother = request.form.get("poor_study_habits_bother")
        else:
            poor_study_habits_bother = None

        poor_in_decision_making = bool(request.form.get("poor_in_decision_making"))
        poor_in_decision_making_when = request.form.get("poor_in_decision_making_when")
        if poor_in_decision_making:
            poor_in_decision_making_bother = request.form.get("poor_in_decision_making_bother")
        else:
            poor_in_decision_making_bother = None

        impulsivity = bool(request.form.get("impulsivity"))
        impulsivity_when = request.form.get("impulsivity_when")
        if impulsivity:
            impulsivity_bother = request.form.get("impulsivity_bother")
        else:
            impulsivity_bother = None

        poor_sleeping_habits = bool(request.form.get("poor_sleeping_habits"))
        poor_sleeping_habits_when = request.form.get("poor_sleeping_habits_when")
        if poor_sleeping_habits:
            poor_sleeping_habits_bother = request.form.get("poor_sleeping_habits_bother")
        else:
            poor_sleeping_habits_bother = None

        loos_of_appetite = bool(request.form.get("loos_of_appetite"))
        loos_of_appetite_when = request.form.get("loos_of_appetite_when")
        if loos_of_appetite:
            loos_of_appetite_bother = request.form.get("loos_of_appetite_bother")
        else:
            loos_of_appetite_bother = None

        over_eating = bool(request.form.get("over_eating"))
        over_eating_when = request.form.get("over_eating_when")
        if over_eating:
            over_eating_bother = request.form.get("over_eating_bother")
        else:
            over_eating_bother = None

        poor_hygiene = bool(request.form.get("poor_hygiene"))
        poor_hygiene_when = request.form.get("poor_hygiene_when")
        if poor_hygiene:
            poor_hygiene_bother = request.form.get("poor_hygiene_bother")
        else:
            poor_hygiene_bother = None

        withdrawal_isolation = bool(request.form.get("withdrawal_isolation"))
        withdrawal_isolation_when = request.form.get("withdrawal_isolation_when")
        if withdrawal_isolation:
            withdrawal_isolation_bother = request.form.get("withdrawal_isolation_bother")
        else:
            withdrawal_isolation_bother = None

        family_problem = bool(request.form.get("family_problem"))
        family_problem_when = request.form.get("family_problem_when")
        if family_problem:
            family_problem_bother = request.form.get("family_problem_bother")
        else:
            family_problem_bother = None

        other_relationship_problem = bool(request.form.get("other_relationship_problem"))
        other_relationship_problem_when = request.form.get("other_relationship_problem_when")
        if other_relationship_problem:
            other_relationship_problem_bother = request.form.get("other_relationship_problem_bother")
        else:
            other_relationship_problem_bother = None

        alcohol_addiction = bool(request.form.get("alcohol_addiction"))
        alcohol_addiction_when = request.form.get("alcohol_addiction_when")
        if alcohol_addiction:
            alcohol_addiction_bother = request.form.get("alcohol_addiction_bother")
        else:
            alcohol_addiction_bother = None

        gambling_addiction = bool(request.form.get("gambling_addiction"))
        gambling_addiction_when = request.form.get("gambling_addiction_when")
        if gambling_addiction:
            gambling_addiction_bother = request.form.get("gambling_addiction_bother")
        else:
            gambling_addiction_bother = None

        drug_addiction = bool(request.form.get("drug_addiction"))
        drug_addiction_when = request.form.get("drug_addiction_when")
        if drug_addiction:
            drug_addiction_bother = request.form.get("drug_addiction_bother")
        else:
            drug_addiction_bother = None

        computer_addiction = bool(request.form.get("computer_addiction"))
        computer_addiction_when = request.form.get("computer_addiction_when")
        if computer_addiction:
            computer_addiction_bother = request.form.get("computer_addiction_bother")
        else:
            computer_addiction_bother = None

        sexual_harassment = bool(request.form.get("sexual_harassment"))
        sexual_harassment_when = request.form.get("sexual_harassment_when")
        if sexual_harassment:
            sexual_harassment_bother = request.form.get("sexual_harassment_bother")
        else:
            sexual_harassment_bother = None

        sexual_abuse = bool(request.form.get("sexual_abuse"))
        sexual_abuse_when = request.form.get("sexual_abuse_when")
        if sexual_abuse:
            sexual_abuse_bother = request.form.get("sexual_abuse_bother")
        else:
            sexual_abuse_bother = None

        physical_abuse = bool(request.form.get("physical_abuse"))
        physical_abuse_when = request.form.get("physical_abuse_when")
        if physical_abuse:
            physical_abuse_bother = request.form.get("physical_abuse_bother")
        else:
            physical_abuse_bother = None

        verbal_abuse = bool(request.form.get("verbal_abuse"))
        verbal_abuse_when = request.form.get("verbal_abuse_when")
        if verbal_abuse:
            verbal_abuse_bother = request.form.get("verbal_abuse_bother")
        else:
            verbal_abuse_bother = None

        pre_marital_sex = bool(request.form.get("pre_marital_sex"))
        pre_marital_sex_when = request.form.get("pre_marital_sex_when")
        if pre_marital_sex:
            pre_marital_sex_bother = request.form.get("pre_marital_sex_bother")
        else:
            pre_marital_sex_bother = None

        teenage_pregnancy = bool(request.form.get("teenage_pregnancy"))
        teenage_pregnancy_when = request.form.get("teenage_pregnancy_when")
        if teenage_pregnancy:
            teenage_pregnancy_bother = request.form.get("teenage_pregnancy_bother")
        else:
            teenage_pregnancy_bother = None

        abortion = bool(request.form.get("abortion"))
        abortion_when = request.form.get("abortion_when")
        if abortion:
            abortion_bother = request.form.get("abortion_bother")
        else:
            abortion_bother = None

        extra_marital_affairs = bool(request.form.get("extra_marital_affairs"))
        extra_marital_affairs_when = request.form.get("extra_marital_affairs_when")
        if extra_marital_affairs:
            extra_marital_affairs_bother = request.form.get("extra_marital_affairs_bother")
        else:
            extra_marital_affairs_bother = None

        psychiatrist_before = request.form.get("psychiatrist_before")
        psychiatrist_reason = request.form.get("psychiatrist_reason")
        psychiatrist_when = request.form.get("psychiatrist_when")

        psychologist_before = request.form.get("psychologist_before")
        psychologist_reason = request.form.get("psychologist_reason")
        psychologist_when = request.form.get("psychologist_when")

        counselor_before = request.form.get("counselor_before")
        counselor_reason = request.form.get("counselor_reason")
        counselor_when = request.form.get("counselor_when")

        personal_description = request.form.get("personal_description")

        cur.execute("""
            INSERT INTO personal_information (
                student_id, nickname, present_address, provincial_address,
                date_of_birth, place_of_birth, age, birth_order, siblings_count,
                civil_status, religion, nationality, home_phone, mobile_no, email,
                weight, height, blood_type, hobbies, talents,
                emergency_name, emergency_relationship, emergency_address, emergency_contact
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            student_id, nickname, present_address, provincial_address,
            date_of_birth, place_of_birth, age, birth_order, siblings_count,
            civil_status, religion, nationality, home_phone, mobile_no, email,
            weight, height, blood_type, hobbies, talents,
            emergency_name, emergency_relationship, emergency_address, emergency_contact
        ))

        cur.execute("""
            INSERT INTO family_background (
                student_id, father_name, father_age, father_education, father_occupation,
                father_income, father_contact, mother_name, mother_age, mother_education,
                mother_occupation, mother_income, mother_contact
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            student_id, father_name, father_age, father_education, father_occupation,
            father_income, father_contact, mother_name, mother_age, mother_education,
            mother_occupation, mother_income, mother_contact
        ))

        cur.execute("""
            INSERT INTO status_of_parent (
                student_id, married_living_together, living_not_married, legally_separated,
                mother_widow, father_widower, separated, father_another_family, mother_another_family
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            student_id, married_living_together, living_not_married, legally_separated,
            mother_widow, father_widower, separated, father_another_family, mother_another_family
        ))

        cur.execute("""
            INSERT INTO academic_information (
                student_id, elementary_school_name, elementary_year_graduated, elementary_awards,
                junior_high_school_name, junior_high_year_graduated, junior_high_awards,
                senior_high_school_name, senior_high_year_graduated, senior_high_awards,
                senior_high_track, senior_high_strand, subject_interested, org_membership,
                study_finance, course_personal_choice, influenced_by, feeling_about_course, personal_choice
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            student_id, elementary_school_name, elementary_year_graduated, elementary_awards,
            junior_high_school_name, junior_high_year_graduated, junior_high_awards,
            senior_high_school_name, senior_high_year_graduated, senior_high_awards,
            senior_high_track, senior_high_strand, subject_interested, org_membership,
            study_finance, True if course_personal_choice == "yes" else False, 
            influenced_by, feeling_about_course, personal_choice
        ))

        cur.execute("""
            INSERT INTO cpsu_enrollment_reason (student_id, reasons, other_reason)
            VALUES (%s, %s, %s)
        """, (student_id, reasons_str, other_reason))

        cur.execute("""
            INSERT INTO other_schools_considered (student_id, school_choices, other_school)
            VALUES (%s, %s, %s)
        """, (student_id, other_schools_str, other_school_text))

        cur.execute("""
            INSERT INTO behavior_information (
                student_id, bullying, bullying_when, bullying_bother,
                suicidal_thoughts, suicidal_thoughts_when, suicidal_thoughts_bother,
                suicidal_attempts, suicidal_attempts_when, suicidal_attempts_bother,
                panic_attacks, panic_attacks_when, panic_attacks_bother,
                anxiety, anxiety_when, anxiety_bother,
                depression, depression_when, depression_bother,
                self_anger_issues, self_anger_issues_when, self_anger_issues_bother,
                recurring_negative_thoughts, recurring_negative_thoughts_when, recurring_negative_thoughts_bother,
                low_self_esteem, low_self_esteem_when, low_self_esteem_bother,
                poor_study_habits, poor_study_habits_when, poor_study_habits_bother,
                poor_in_decision_making, poor_in_decision_making_when, poor_in_decision_making_bother,
                impulsivity, impulsivity_when, impulsivity_bother,
                poor_sleeping_habits, poor_sleeping_habits_when, poor_sleeping_habits_bother,
                loos_of_appetite, loos_of_appetite_when, loos_of_appetite_bother,
                over_eating, over_eating_when, over_eating_bother,
                poor_hygiene, poor_hygiene_when, poor_hygiene_bother,
                withdrawal_isolation, withdrawal_isolation_when, withdrawal_isolation_bother,
                family_problem, family_problem_when, family_problem_bother,
                other_relationship_problem, other_relationship_problem_when, other_relationship_problem_bother,
                alcohol_addiction, alcohol_addiction_when, alcohol_addiction_bother,
                gambling_addiction, gambling_addiction_when, gambling_addiction_bother,
                drug_addiction, drug_addiction_when, drug_addiction_bother,
                computer_addiction, computer_addiction_when, computer_addiction_bother,
                sexual_harassment, sexual_harassment_when, sexual_harassment_bother,
                sexual_abuse, sexual_abuse_when, sexual_abuse_bother,
                physical_abuse, physical_abuse_when, physical_abuse_bother,
                verbal_abuse, verbal_abuse_when, verbal_abuse_bother,
                pre_marital_sex, pre_marital_sex_when, pre_marital_sex_bother,
                teenage_pregnancy, teenage_pregnancy_when, teenage_pregnancy_bother,
                abortion, abortion_when, abortion_bother,
                extra_marital_affairs, extra_marital_affairs_when, extra_marital_affairs_bother
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            student_id, bullying, bullying_when, bullying_bother,
            suicidal_thoughts, suicidal_thoughts_when, suicidal_thoughts_bother,
            suicidal_attempts, suicidal_attempts_when, suicidal_attempts_bother,
            panic_attacks, panic_attacks_when, panic_attacks_bother,
            anxiety, anxiety_when, anxiety_bother,
            depression, depression_when, depression_bother,
            self_anger_issues, self_anger_issues_when, self_anger_issues_bother,
            recurring_negative_thoughts, recurring_negative_thoughts_when, recurring_negative_thoughts_bother,
            low_self_esteem, low_self_esteem_when, low_self_esteem_bother,
            poor_study_habits, poor_study_habits_when, poor_study_habits_bother,
            poor_in_decision_making, poor_in_decision_making_when, poor_in_decision_making_bother,
            impulsivity, impulsivity_when, impulsivity_bother,
            poor_sleeping_habits, poor_sleeping_habits_when, poor_sleeping_habits_bother,
            loos_of_appetite, loos_of_appetite_when, loos_of_appetite_bother,
            over_eating, over_eating_when, over_eating_bother,
            poor_hygiene, poor_hygiene_when, poor_hygiene_bother,
            withdrawal_isolation, withdrawal_isolation_when, withdrawal_isolation_bother,
            family_problem, family_problem_when, family_problem_bother,
            other_relationship_problem, other_relationship_problem_when, other_relationship_problem_bother,
            alcohol_addiction, alcohol_addiction_when, alcohol_addiction_bother,
            gambling_addiction, gambling_addiction_when, gambling_addiction_bother,
            drug_addiction, drug_addiction_when, drug_addiction_bother,
            computer_addiction, computer_addiction_when, computer_addiction_bother,
            sexual_harassment, sexual_harassment_when, sexual_harassment_bother,
            sexual_abuse, sexual_abuse_when, sexual_abuse_bother,
            physical_abuse, physical_abuse_when, physical_abuse_bother,
            verbal_abuse, verbal_abuse_when, verbal_abuse_bother,
            pre_marital_sex, pre_marital_sex_when, pre_marital_sex_bother,
            teenage_pregnancy, teenage_pregnancy_when, teenage_pregnancy_bother,
            abortion, abortion_when, abortion_bother,
            extra_marital_affairs, extra_marital_affairs_when, extra_marital_affairs_bother
        ))

        cur.execute("""
            INSERT INTO psychological_consultations (
                student_id,
                psychiatrist_before, psychiatrist_reason, psychiatrist_when,
                psychologist_before, psychologist_reason, psychologist_when,
                counselor_before, counselor_reason, counselor_when
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            student_id,
            psychiatrist_before, psychiatrist_reason, psychiatrist_when,
            psychologist_before, psychologist_reason, psychologist_when,
            counselor_before, counselor_reason, counselor_when
        ))

        cur.execute("""
            INSERT INTO personal_descriptions (
                student_id,personal_description
            )
            VALUES (%s,%s)
        """, (
            student_id,personal_description
        ))

        cur.execute("""
            INSERT INTO notifications (student_id, exam_id, message)
            VALUES (%s, %s, %s)
        """, (student_id, session["exam_id"], "Student Inventory Form Submitted Successfully!"))
        
        conn.commit()
        cur.close()
        conn.close()

        flash("Inventory form submitted successfully!", "success")
        return redirect(url_for("student.home"))

    cur.execute("SELECT fullname, gender, email FROM student WHERE id = %s", (student_id,))
    student = cur.fetchone()
    cur.close()
    conn.close()

    return render_template("student/studentInventoryForm.html", student=student)

@student_bp.route("/studentInventoryResult")
def studentInventoryResult():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))
    
    student_id = session["student_id"]
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT result_unlocked, inventory_result_unlocked
        FROM notifications
        WHERE student_id = %s
        ORDER BY id DESC LIMIT 1
    """, (session["student_id"],))
    row = cur.fetchone()

    cur.execute("""
        SELECT
            MAX(CASE WHEN result_unlocked = TRUE THEN 1 ELSE 0 END),
            MAX(CASE WHEN inventory_result_unlocked = TRUE THEN 1 ELSE 0 END)
        FROM notifications
        WHERE student_id = %s
    """, (session["student_id"],))

    survey_result_unlocked, inventory_result_unlocked = cur.fetchone()

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
        "student/studentInventoryResult.html",
    student_id=session["student_id"],
        info=info,
        student_photo_base64=student_photo_base64,
        selected_reasons=selected_reasons,
        other_reason=other_reason,
        other_schools_selected=other_schools_selected,
        other_school=other_school,
        survey_result_unlocked=survey_result_unlocked,
        inventory_result_unlocked=inventory_result_unlocked
    )

@student_bp.route('/download_inventory_pdf/<int:student_id>')
def download_inventory_pdf(student_id):
    if "student_id" not in session or session["student_id"] != student_id:
        return redirect(url_for("student.login_page"))

    conn = get_db_connection()

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT 
            s.id AS id,
            s.exam_id, s.fullname, s.gender, s.email, s.campus, s.photo,
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

    student_data = {
        "exam_id": info[1],
        "fullname": info[2]
    }

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

    cpsu_logo_base64 = image_to_base64("cpsulogo.png")

    html = render_template(
        "student/studentInventoryResultPDF.html",
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

    filename = f"Inventory_Result_{student_data['exam_id']}_{student_data['fullname'].replace(' ', '_')}.pdf"

    return send_file(
        pdf_io,
        mimetype="application/pdf",
        download_name=filename,
        as_attachment=True
    )

@student_bp.route("/profile", methods=["GET", "POST"])
def profile():
    if "student_id" not in session:
        return redirect(url_for("student.login_page"))

    student_id = session["student_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        fullname = request.form.get("fullname")
        gender = request.form.get("gender")
        email = request.form.get("email")

        if fullname and gender and email:
            cur.execute("""
                UPDATE student
                SET fullname = %s,
                    gender = %s,
                    email = %s
                WHERE id = %s
            """, (fullname, gender, email, student_id))
            conn.commit()

    cur.execute("""
        SELECT fullname, gender, email, photo
        FROM student
        WHERE id = %s
    """, (student_id,))
    
    row = cur.fetchone()

    student = {
        "fullname": row[0],
        "gender": row[1],
        "email": row[2],
        "photo": row[3],
    }

    cur.execute("""
        SELECT result_unlocked, inventory_result_unlocked
        FROM notifications
        WHERE student_id = %s
        ORDER BY id DESC LIMIT 1
    """, (student_id,))
    notif = cur.fetchone()

    cur.execute("""
        SELECT
            MAX(CASE WHEN result_unlocked = TRUE THEN 1 ELSE 0 END),
            MAX(CASE WHEN inventory_result_unlocked = TRUE THEN 1 ELSE 0 END)
        FROM notifications
        WHERE student_id = %s
    """, (session["student_id"],))

    survey_result_unlocked, inventory_result_unlocked = cur.fetchone()

    cur.close()
    conn.close()

    return render_template(
        "student/profile.html",
        student=student,
        survey_result_unlocked=survey_result_unlocked,
        inventory_result_unlocked=inventory_result_unlocked
    )

@student_bp.route("/upload_student_photo", methods=["POST"])
def upload_student_photo():
    if "exam_id" not in session or "student_id" not in session:
        return redirect(url_for("student.login_page"))

    conn = get_db_connection()
    cur = conn.cursor()

    file = request.files.get("photo")
    if not file or file.filename == "":
        flash("No file selected", "error")
        conn.close()
        return redirect(url_for("student.surveyResult"))

    if not allowed_file(file.filename):
        flash("Invalid file type", "error")
        conn.close()
        return redirect(url_for("student.surveyResult"))

    try:
        # ✅ OPEN IMAGE SAFELY
        image = Image.open(file).convert("RGB")
    except Exception:
        flash("Invalid image file.", "error")
        conn.close()
        return redirect(url_for("student.surveyResult"))

    # ✂ AUTO-CROP TO 1x1
    width, height = image.size
    size = min(width, height)
    left = (width - size) / 2
    top = (height - size) / 2
    right = left + size
    bottom = top + size

    image = image.crop((left, top, right, bottom))
    image = image.resize((300, 300))  # high quality

    # ✅ SAVE LOCATION (STATIC FOLDER)
    upload_folder = os.path.join(
        current_app.static_folder,
        "uploads",
        "students"
    )
    os.makedirs(upload_folder, exist_ok=True)

    new_filename = f"exam_{session['exam_id']}.jpg"

    file_path = os.path.join(upload_folder, new_filename)
    image.save(file_path, "JPEG", quality=95)

    # ✅ SAVE TO DATABASE
    cur.execute(
        "UPDATE student SET photo = %s WHERE id = %s",
        (new_filename, session["student_id"])
    )
    conn.commit()
    conn.close()

    flash("1×1 photo uploaded successfully", "success")
    return redirect(url_for("student.surveyResult"))

@student_bp.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("student.login_page"))
