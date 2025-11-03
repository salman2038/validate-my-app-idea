# app.py — Full, integrated version (restore admin routes + multi-step form + Google OAuth + migrations)
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3, os, json
from dotenv import load_dotenv
from datetime import datetime
from functools import wraps
os.makedirs("reports", exist_ok=True)

# Your project logic utilities (must exist)
from logic.score_engine import calculate_complexity, calculate_financial_viability
from logic.gemini_api import call_gemini

# Optional PDF generator helpers you wrote
# logic/pdf_generator.py should provide generate_pdf(...) or generate_pdf_report(...)
try:
    from logic.pdf_generator import generate_pdf_report
except Exception:
    generate_pdf = None
    generate_pdf_report = None

# Google OAuth libs (used for "Login with Google")
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from google.oauth2 import id_token

# ---------- App init ----------
app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your_secret_key")
DB_NAME = "datarector.db"

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# For local development
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Ensure reports folder
os.makedirs("reports", exist_ok=True)

# ---------- DB: base creation + migrations ----------
def init_db():
    """Create the primary table (phase2_inputs) if missing."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS phase2_inputs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT,
        core_problem_statement TEXT,
        user_role_segment TEXT,
        monetization_model TEXT,
        current_solution_inefficiency TEXT,
        unique_value_proposition TEXT,
        primary_competitors_text TEXT,
        must_have_features_list TEXT,
        arpu_estimate_usd REAL,
        acquisition_goal_3mo INTEGER,
        monthly_opex_est_usd REAL,
        dev_budget_range TEXT,
        external_integrations_list TEXT,
        client_post_launch_fear TEXT,
        client_critical_question TEXT,
        complexity_score REAL,
        financial_score REAL,
        ai_verdict TEXT,
        ai_score REAL,
        ai_suggestions TEXT,
        ai_summary TEXT
    )''')
    conn.commit()
    conn.close()

def init_user_table():
    """Create users table and default admin (if missing)."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        name TEXT,
        phone TEXT,
        address TEXT,
        picture TEXT
    )''')
    # Default admin (only if not present)
    c.execute("SELECT * FROM users WHERE email=?", ('admin@app.com',))
    if not c.fetchone():
        hashed_pw = generate_password_hash("admin123")
        c.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
                  ('admin@app.com', hashed_pw, 'admin'))
    conn.commit()
    conn.close()

def auto_migrate_phase2():
    """Add missing columns to phase2_inputs without deleting data."""
    expected = [
        ("target_countries", "TEXT"),
        ("submitter_name", "TEXT"),
        ("submitter_email", "TEXT"),
        ("submitter_phone", "TEXT"),
        ("report_file", "TEXT"),
        ("created_at", "TEXT")
    ]
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("PRAGMA table_info(phase2_inputs)")
    existing = [r[1] for r in c.fetchall()]
    for col, typ in expected:
        if col not in existing:
            try:
                c.execute(f"ALTER TABLE phase2_inputs ADD COLUMN {col} {typ}")
                print(f"✅ Added missing column to phase2_inputs: {col}")
            except Exception as e:
                print(f"⚠️ Could not add {col}: {e}")
    conn.commit()
    conn.close()

def auto_migrate_users_table():
    """Add missing columns to users table."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("PRAGMA table_info(users)")
    existing_cols = [r[1] for r in c.fetchall()]
    new_columns = [
        ("name", "TEXT"),
        ("phone", "TEXT"),
        ("address", "TEXT"),
        ("picture", "TEXT")
    ]
    for col, col_type in new_columns:
        if col not in existing_cols:
            try:
                c.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type}")
                print(f"✅ Added {col} column to users table.")
            except Exception as e:
                print(f"⚠️ Could not add users.{col}: {e}")
    conn.commit()
    conn.close()

# initialize DBs and migrations
init_db()
init_user_table()
auto_migrate_phase2()
auto_migrate_users_table()

# ---------- Helpers ----------
def get_session_value(key):
    return session.get(key, '')

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_email" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_email" not in session or session.get("role") != "admin":
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper

# ---------- Auth: Signup / Local Login ----------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        if not email or not password or not confirm:
            return render_template("signup.html", error="All fields are required.")
        if password != confirm:
            return render_template("signup.html", error="Passwords do not match.")
        hashed_pw = generate_password_hash(password)
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
                      (email, hashed_pw, "user"))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("signup.html", error="Email already exists.")
        conn.close()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    # show login page that may contain "Login with Google" button (template)
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT password, role, name FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        conn.close()
        if row:
            stored_password, role, name = row[0], row[1], row[2]
            if check_password_hash(stored_password, password):
                session["user_email"] = email
                session["role"] = role
                session["user_name"] = name
                # redirect based on role
                if role == "admin":
                    return redirect(url_for("admin_dashboard"))
                return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials.")
    # GET
    return render_template("login.html")

# ---------- Google OAuth routes ----------
@app.route("/login/google")
def login_google():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash("Google OAuth not configured (set GOOGLE_CLIENT_ID/SECRET in .env).", "warning")
        return redirect(url_for("login"))

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["https://validate-my-app-idea.onrender.com/login/callback"]
            }
        },
        scopes=["https://www.googleapis.com/auth/userinfo.email", "openid"],
    )
    flow.redirect_uri = "https://validate-my-app-idea.onrender.com/login/callback"
    auth_url, state = flow.authorization_url(prompt="consent")
    session["oauth_state"] = state
    return redirect(auth_url)

@app.route("/login/callback")
def login_callback():
    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["https://validate-my-app-idea.onrender.com/login/callback"]
                }
            },
            scopes=["https://www.googleapis.com/auth/userinfo.email", "openid"],
        )
        flow.redirect_uri = "https://validate-my-app-idea.onrender.com/login/callback"
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        request_session = google.auth.transport.requests.Request()
        id_info = id_token.verify_oauth2_token(
            id_token=credentials.id_token,
            request=request_session,
            audience=GOOGLE_CLIENT_ID
        )
        user_email = id_info.get("email")
        user_name = id_info.get("name")
        user_picture = id_info.get("picture")
        # Save session
        session["user_email"] = user_email
        session["user_name"] = user_name
        session["user_picture"] = user_picture
        # Create local DB record if missing
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", (user_email,))
        if not c.fetchone():
            c.execute("INSERT INTO users (email, name, role, picture) VALUES (?, ?, ?, ?)",
                      (user_email, user_name or "", "user", user_picture or ""))
            conn.commit()
        conn.close()
        return redirect(url_for("step1"))
    except Exception as e:
        print("Google OAuth callback error:", e)
        flash("Google login failed.", "danger")
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- Dashboard / Admin ----------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user_email=session.get("user_email"), user_name=session.get("user_name"))

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM phase2_inputs")
    total_reports = c.fetchone()[0] or 0
    c.execute("""
        SELECT p.id, p.user_email, p.core_problem_statement, p.ai_verdict, p.ai_score, p.created_at, u.name
        FROM phase2_inputs p
        LEFT JOIN users u ON p.user_email = u.email
        ORDER BY p.id DESC LIMIT 5
    """)
    recent = c.fetchall()
    conn.close()
    recent_list = []
    for r in recent:
        recent_list.append({
            "id": r[0],
            "user_email": r[1],
            "core_problem_statement": r[2],
            "ai_verdict": r[3],
            "ai_score": r[4],
            "created_at": r[5],
            "user_name": r[6]
        })
    return render_template("admin_dashboard.html",
                           total_users=total_users,
                           total_reports=total_reports,
                           recent=recent_list,
                           title="Admin Dashboard")

# Admin - manage users
@app.route("/admin/users")
@admin_required
def admin_users():
    q = request.args.get("q", "").strip()
    role_filter = request.args.get("role", "").strip()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    base_sql = "SELECT id, email, role, name, phone, address, picture FROM users"
    conditions = []
    params = []
    if q:
        likeq = f"%{q}%"
        conditions.append("(email LIKE ? OR name LIKE ? OR phone LIKE ?)")
        params += [likeq, likeq, likeq]
    if role_filter:
        conditions.append("role = ?")
        params.append(role_filter)
    if conditions:
        base_sql += " WHERE " + " AND ".join(conditions)
    base_sql += " ORDER BY id DESC"
    c.execute(base_sql, params)
    users = c.fetchall()
    conn.close()
    return render_template("admin_users.html", users=users, q=q, role_filter=role_filter, title="Manage Users")

# Admin - manage reports
@app.route("/admin/reports")
@admin_required
def admin_reports():
    user_filter = request.args.get("user", "").strip()
    verdict_filter = request.args.get("verdict", "").strip()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    sql = """
        SELECT p.id, p.user_email, u.name, p.submitter_name, p.submitter_email, p.submitter_phone,
               p.target_countries, p.core_problem_statement, p.monetization_model,
               p.complexity_score, p.financial_score, p.ai_verdict, p.ai_score, p.report_file, p.created_at
        FROM phase2_inputs p
        LEFT JOIN users u ON p.user_email = u.email
    """
    conditions = []
    params = []
    if user_filter:
        likeu = f"%{user_filter}%"
        conditions.append("(p.user_email LIKE ? OR u.name LIKE ? OR p.submitter_name LIKE ?)")
        params += [likeu, likeu, likeu]
    if verdict_filter:
        conditions.append("p.ai_verdict = ?")
        params.append(verdict_filter)
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY p.id DESC"
    c.execute(sql, params)
    rows = c.fetchall()
    conn.close()
    submissions = []
    for r in rows:
        submissions.append({
            "id": r[0],
            "user_email": r[1],
            "user_name": r[2] or r[3],
            "submitter_name": r[3],
            "submitter_email": r[4],
            "submitter_phone": r[5],
            "target_countries": r[6],
            "core_problem_statement": r[7],
            "monetization_model": r[8],
            "complexity_score": r[9],
            "financial_score": r[10],
            "ai_verdict": r[11],
            "ai_score": r[12],
            "report_file": r[13],
            "created_at": r[14]
        })
    return render_template("admin_reports.html", submissions=submissions, title="All Reports")

# Admin - delete user
@app.route("/admin/delete_user/<int:user_id>", methods=["POST", "GET"])
@admin_required
def admin_delete_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
    conn.commit()
    conn.close()
    flash("User deleted", "success")
    return redirect(url_for("admin_users"))

# Admin - delete submission
@app.route("/admin/delete_submission/<int:submission_id>", methods=["POST", "GET"])
@admin_required
def admin_delete_submission(submission_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT report_file FROM phase2_inputs WHERE id=?", (submission_id,))
    row = c.fetchone()
    if row and row[0]:
        file_path = os.path.join(os.getcwd(), "reports", os.path.basename(row[0]))
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass
    c.execute("DELETE FROM phase2_inputs WHERE id=?", (submission_id,))
    conn.commit()
    conn.close()
    flash("Submission deleted", "success")
    return redirect(url_for("admin_reports"))

# ---------------------------
# ADMIN: REGENERATE REPORT
# ---------------------------
@app.route("/admin/regenerate_report/<int:report_id>", methods=["POST"])
@admin_required
def regenerate_report(report_id):
    """Re-generate the PDF + AI evaluation for a submission"""
    import sqlite3, os, json
    from datetime import datetime
    from logic.gemini_api import call_gemini
    from logic.pdf_generator import generate_pdf

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM phase2_inputs WHERE id=?", (report_id,))
    row = c.fetchone()
    if not row:
        flash("Report not found", "danger")
        return redirect(url_for("admin_reports"))

    cols = [d[0] for d in c.description]
    data = dict(zip(cols, row))
    conn.close()

    ai_result = call_gemini(data)

    # ✅ Correct consistent filename
    safe_user = (data.get("submitter_email") or data.get("user_email") or "user").split("@")[0]
    file_name = f"report_{safe_user}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    file_path = os.path.join("reports", file_name)

    # Generate PDF and save in reports folder
    generate_pdf({
        "user_email": data.get("submitter_email") or data.get("user_email"),
        "verdict": ai_result.get("verdict"),
        "ai_score": ai_result.get("ai_score"),
        "summary": ai_result.get("summary", {}),
        "suggestions": ai_result.get("suggestions", []),
        "submitter_name": data.get("submitter_name"),
        "submitter_phone": data.get("submitter_phone"),
        "target_countries": data.get("target_countries")
    }, file_path)

    # ✅ Save only filename (not full path)
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        UPDATE phase2_inputs
        SET ai_verdict=?, ai_score=?, ai_suggestions=?, ai_summary=?, report_file=?, created_at=?
        WHERE id=?
    """, (
        ai_result.get("verdict"),
        ai_result.get("ai_score"),
        json.dumps(ai_result.get("suggestions", [])),
        json.dumps(ai_result.get("summary", {})),
        file_name,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        report_id
    ))
    conn.commit()
    conn.close()

    flash("✅ Report regenerated successfully!", "success")
    return redirect(url_for("admin_reports"))

# Admin - update user
@app.route("/admin/update_user", methods=["POST"])
@admin_required
def admin_update_user():
    user_id = request.form.get("id")
    name = request.form.get("name")
    phone = request.form.get("phone")
    address = request.form.get("address")
    role = request.form.get("role", "user")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        UPDATE users
        SET name = ?, phone = ?, address = ?, role = ?
        WHERE id = ?
    """, (name, phone, address, role, user_id))
    conn.commit()
    conn.close()
    flash("User updated", "success")
    return redirect(url_for("admin_users"))

# ---------- Multi-step form routes ----------
@app.route("/")
def index():
    if "user_email" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("step1"))

@app.route("/step1", methods=["GET", "POST"])
@login_required
def step1():
    if request.method == "POST":
        session['core_problem_statement'] = request.form.get('core_problem_statement', '')
        session['user_role_segment'] = ', '.join(request.form.getlist('user_role_segment'))
        session['monetization_model'] = ', '.join(request.form.getlist('monetization_model'))
        if not session['core_problem_statement'] or not session['user_role_segment'] or not session['monetization_model']:
            return render_template('step1.html', error="Please fill all fields before continuing.",
                                   core_problem_statement=session.get('core_problem_statement', ''),
                                   user_role_segment=session.get('user_role_segment', ''),
                                   monetization_model=session.get('monetization_model', ''),
                                   active_step=1, show_stepper=True)
        return redirect(url_for("step2"))
    return render_template('step1.html',
                           active_step=1,
                           core_problem_statement=get_session_value('core_problem_statement'),
                           user_role_segment=get_session_value('user_role_segment'),
                           monetization_model=get_session_value('monetization_model'),
                           show_stepper=True)

@app.route("/step2", methods=["GET", "POST"])
@login_required
def step2():
    if request.method == "POST":
        session['current_solution_inefficiency'] = request.form.get('current_solution_inefficiency', '')
        session['unique_value_proposition'] = request.form.get('unique_value_proposition', '')
        session['primary_competitors_text'] = request.form.get('primary_competitors_text', '')
        # features may come from multi-select; append "Other" hidden value if present
        selected_features = request.form.getlist('must_have_features_list')
        # if a separate single hidden field (other) exists, the template appended it with same name
        session['must_have_features_list'] = ', '.join(selected_features)
        session['target_countries'] = ', '.join(request.form.getlist('target_countries'))
        if not session['unique_value_proposition'] or not session['primary_competitors_text']:
            return render_template('step2.html',
                                   error="Please complete all required fields before continuing.",
                                   active_step=2, show_stepper=True)
        return redirect(url_for("step3"))
    return render_template('step2.html',
                           active_step=2,
                           current_solution_inefficiency=get_session_value('current_solution_inefficiency'),
                           unique_value_proposition=get_session_value('unique_value_proposition'),
                           primary_competitors_text=get_session_value('primary_competitors_text'),
                           must_have_features_list=get_session_value('must_have_features_list'),
                           target_countries=get_session_value('target_countries'),
                           show_stepper=True)

@app.route("/step3", methods=["GET", "POST"])
@login_required
def step3():
    if request.method == "POST":
        # personal details
        session['submitter_name'] = request.form.get('user_name', '')
        session['submitter_email'] = request.form.get('user_email', '')
        session['submitter_phone'] = request.form.get('user_phone', '')
        # financial
        session['arpu_estimate_usd'] = request.form.get('arpu_estimate_usd', '')
        session['acquisition_goal_3mo'] = request.form.get('acquisition_goal_3mo', '')
        session['monthly_opex_est_usd'] = request.form.get('monthly_opex_est_usd', '')
        session['dev_budget_range'] = request.form.get('dev_budget_range', '')
        session['external_integrations_list'] = ', '.join(request.form.getlist('external_integrations_list'))
        session['client_post_launch_fear'] = request.form.get('client_post_launch_fear', '')
        session['client_critical_question'] = request.form.get('client_critical_question', '')

        # validate required financials
        if not session['arpu_estimate_usd'] or not session['acquisition_goal_3mo'] or not session['monthly_opex_est_usd']:
            return render_template('step3.html', error="Please complete all required fields before submitting.",
                                   active_step=3, show_stepper=True)

        # compute scores
        complexity_score = calculate_complexity(session.get('must_have_features_list', ''), session.get('external_integrations_list', ''))
        financial_score = calculate_financial_viability(session.get('arpu_estimate_usd', ''), session.get('acquisition_goal_3mo', ''), session.get('monthly_opex_est_usd', ''))

        # persist submission
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''INSERT INTO phase2_inputs (
            user_email, core_problem_statement, user_role_segment, monetization_model,
            current_solution_inefficiency, unique_value_proposition, primary_competitors_text,
            must_have_features_list, arpu_estimate_usd, acquisition_goal_3mo,
            monthly_opex_est_usd, dev_budget_range, external_integrations_list,
            client_post_launch_fear, client_critical_question,
            complexity_score, financial_score,
            target_countries, submitter_name, submitter_email, submitter_phone
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
            session.get('user_email'),
            session.get('core_problem_statement'),
            session.get('user_role_segment'),
            session.get('monetization_model'),
            session.get('current_solution_inefficiency'),
            session.get('unique_value_proposition'),
            session.get('primary_competitors_text'),
            session.get('must_have_features_list'),
            session.get('arpu_estimate_usd'),
            session.get('acquisition_goal_3mo'),
            session.get('monthly_opex_est_usd'),
            session.get('dev_budget_range'),
            session.get('external_integrations_list'),
            session.get('client_post_launch_fear'),
            session.get('client_critical_question'),
            complexity_score,
            financial_score,
            session.get('target_countries'),
            session.get('submitter_name'),
            session.get('submitter_email'),
            session.get('submitter_phone')
        ))
        conn.commit()
        conn.close()

        # ✅ Prepare user inputs once
        user_inputs = {k: session.get(k, '') for k in [
            "core_problem_statement", "user_role_segment", "monetization_model",
            "current_solution_inefficiency", "unique_value_proposition", "primary_competitors_text",
            "must_have_features_list", "arpu_estimate_usd", "acquisition_goal_3mo",
            "monthly_opex_est_usd", "external_integrations_list",
            "client_post_launch_fear", "client_critical_question"
        ]}

        # ✅ Validate
        from logic.validation import validate_app_idea
        is_valid, reason = validate_app_idea(user_inputs)
        if not is_valid:
            return render_template(
                'result.html',
                verdict="❌ Invalid Submission",
                ai_score=0,
                summary={"error": reason},
                suggestions=[]
            )

        # ✅ Call Gemini AI safely
        try:
            ai_result = call_gemini(user_inputs)
        except Exception as e:
            print("Gemini call error:", e)
            ai_result = {"verdict": "Error", "ai_score": None, "suggestions": [], "summary": {}}

        # ✅ Generate PDF
        file_name = f"report_{(session.get('submitter_email') or session.get('user_email') or 'user').split('@')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        file_path = os.path.join("reports", file_name)
        try:
            if generate_pdf:
                generate_pdf({
                    "user_email": session.get("submitter_email") or session.get("user_email"),
                    "verdict": ai_result.get("verdict"),
                    "ai_score": ai_result.get("ai_score"),
                    "summary": ai_result.get("summary", {}),
                    "suggestions": ai_result.get("suggestions", []),
                    "submitter_name": session.get("submitter_name"),
                    "submitter_phone": session.get("submitter_phone"),
                    "target_countries": session.get("target_countries")
                }, file_path)
            elif generate_pdf_report:
                pdf_path = generate_pdf_report(session.get("submitter_email") or session.get("user_email"), ai_result)
                file_path = pdf_path
                file_name = os.path.basename(pdf_path)
            else:
                with open(file_path, "wb") as f:
                    f.write(b"")
        except Exception as e:
            print("PDF generation error:", e)
            with open(file_path, "wb") as f:
                f.write(b"")

        # ✅ Update DB with AI results
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            UPDATE phase2_inputs
            SET ai_verdict = ?, ai_score = ?, ai_suggestions = ?, ai_summary = ?,
                report_file = ?, created_at = ?
            WHERE id = (SELECT MAX(id) FROM phase2_inputs)
        ''', (
            ai_result.get("verdict"),
            ai_result.get("ai_score"),
            json.dumps(ai_result.get("suggestions", [])),
            json.dumps(ai_result.get("summary", {})),
            file_name,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conn.close()
            # ✅ Keep login session
        keep = {k: session.get(k) for k in ["user_email", "role", "user_name", "user_picture"]}
        session.clear()
        session.update({k: v for k, v in keep.items() if v})

        # ✅ Show AI results
        return render_template('result.html',
                               verdict=ai_result.get("verdict"),
                               ai_score=ai_result.get("ai_score"),
                               suggestions=ai_result.get("suggestions", []),
                               summary=ai_result.get("summary", {}))

    return render_template('step3.html', active_step=3, show_stepper=True)   

# ---------- Reports (user) ----------
@app.route("/reports")
@login_required
def reports():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, ai_verdict, ai_score, report_file, created_at FROM phase2_inputs WHERE submitter_email = ? OR user_email = ? ORDER BY id DESC", (session.get("user_email"), session.get("user_email")))
    rows = c.fetchall()
    conn.close()
    reports_data = []
    for r in rows:
        reports_data.append({
            "id": r[0],
            "ai_verdict": r[1],
            "ai_score": r[2],
            "report_file": r[3],
            "created_at": r[4]
        })
    return render_template("reports.html", reports=reports_data, title="Reports")

# Download single report file
@app.route("/download/<path:filename>")
@login_required
def download_report(filename):
    REPORTS_FOLDER = os.path.join(os.getcwd(), "reports")
    path = os.path.join(REPORTS_FOLDER, os.path.basename(filename))
    if not os.path.exists(path):
        return f"❌ File not found: {path}", 404
    return send_file(path, as_attachment=True)

# ---------- Dev: reset DB (admin only) ----------
@app.route("/reset-db")
@admin_required
def reset_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS phase2_inputs")
    conn.commit()
    conn.close()
    init_db()
    auto_migrate_phase2()
    flash("Database reset and migrated.", "success")
    return redirect(url_for("admin_dashboard"))

# ---------- Run ----------
# if __name__ == "__main__":
#     print("Starting App — DB:", DB_NAME)
#     app.run(debug=True)
if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=8080)