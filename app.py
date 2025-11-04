# app.py — PostgreSQL / psycopg2 version (full, all routes preserved)
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import os, json, psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from datetime import datetime
from functools import wraps

# Ensure the reports directory exists
os.makedirs("reports", exist_ok=True)
load_dotenv()

# Project logic utilities
from logic.score_engine import calculate_complexity, calculate_financial_viability
from logic.gemini_api import call_gemini

# Optional PDF generator helpers
try:
    from logic.pdf_generator import generate_pdf_report, generate_pdf
except Exception:
    generate_pdf = None
    generate_pdf_report = None

# Google OAuth libs
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from google.oauth2 import id_token

# ---------- App init ----------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your_secret_key")

# DB config — expects full DATABASE_URL like: postgres://user:pass@host:port/dbname
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Don't crash in local dev if you still want to use a local SQLite file — but user requested PG migration,
    # so require DATABASE_URL in production/deploy.
    raise RuntimeError("DATABASE_URL environment variable is required for PostgreSQL migration.")

def get_db_connection():
    # return a new connection; use RealDictCursor where convenient
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# ---------- DB creation / migrations ----------
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS phase2_inputs (
            id SERIAL PRIMARY KEY,
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
            ai_summary TEXT,
            target_countries TEXT,
            submitter_name TEXT,
            submitter_email TEXT,
            submitter_phone TEXT,
            report_file TEXT,
            created_at TEXT
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

def init_user_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            name TEXT,
            phone TEXT,
            address TEXT,
            picture TEXT
        );
    """)
    # ensure default admin exists
    cur.execute("SELECT id FROM users WHERE email=%s", ('admin@app.com',))
    if not cur.fetchone():
        hashed_pw = generate_password_hash("admin123")
        cur.execute("INSERT INTO users (email, password, role) VALUES (%s, %s, %s)",
                    ('admin@app.com', hashed_pw, 'admin'))
    conn.commit()
    cur.close()
    conn.close()

# Run initial creation
init_db()
init_user_table()

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
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (email, password, role) VALUES (%s, %s, %s)",
                        (email, hashed_pw, "user"))
            conn.commit()
        except psycopg2.IntegrityError:
            conn.rollback()
            conn.close()
            return render_template("signup.html", error="Email already exists.")
        cur.close()
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
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password, role, name FROM users WHERE email=%s", (email,))
        row = cur.fetchone()
        cur.close()
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
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# For local development allow insecure transport — on production Render you won't need this.
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

@app.route("/login/google")
def login_google():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash("Google OAuth not configured (set GOOGLE_CLIENT_ID/SECRET in environment).", "warning")
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
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", (user_email,))
        if not cur.fetchone():
            cur.execute("INSERT INTO users (email, name, role, picture) VALUES (%s, %s, %s, %s)",
                        (user_email, user_name or "", "user", user_picture or ""))
            conn.commit()
        cur.close()
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
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0] or 0
    cur.execute("SELECT COUNT(*) FROM phase2_inputs")
    total_reports = cur.fetchone()[0] or 0
    cur.execute("""
        SELECT p.id, p.user_email, p.core_problem_statement, p.ai_verdict, p.ai_score, p.created_at, u.name
        FROM phase2_inputs p
        LEFT JOIN users u ON p.user_email = u.email
        ORDER BY p.id DESC LIMIT 5
    """)
    recent = cur.fetchall()
    cur.close()
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
    conn = get_db_connection()
    cur = conn.cursor()
    base_sql = "SELECT id, email, role, name, phone, address, picture FROM users"
    conditions = []
    params = []
    if q:
        likeq = f"%{q}%"
        conditions.append("(email ILIKE %s OR name ILIKE %s OR phone ILIKE %s)")
        params += [likeq, likeq, likeq]
    if role_filter:
        conditions.append("role = %s")
        params.append(role_filter)
    if conditions:
        base_sql += " WHERE " + " AND ".join(conditions)
    base_sql += " ORDER BY id DESC"
    cur.execute(base_sql, params)
    users = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("admin_users.html", users=users, q=q, role_filter=role_filter, title="Manage Users")

# Admin - manage reports
@app.route("/admin/reports")
@admin_required
def admin_reports():
    user_filter = request.args.get("user", "").strip()
    verdict_filter = request.args.get("verdict", "").strip()
    conn = get_db_connection()
    cur = conn.cursor()
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
        conditions.append("(p.user_email ILIKE %s OR u.name ILIKE %s OR p.submitter_name ILIKE %s)")
        params += [likeu, likeu, likeu]
    if verdict_filter:
        conditions.append("p.ai_verdict = %s")
        params.append(verdict_filter)
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY p.id DESC"
    cur.execute(sql, params)
    rows = cur.fetchall()
    cur.close()
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
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = %s AND role != 'admin'", (user_id,))
    conn.commit()
    cur.close()
    conn.close()
    flash("User deleted", "success")
    return redirect(url_for("admin_users"))

# Admin - delete submission
@app.route("/admin/delete_submission/<int:submission_id>", methods=["POST", "GET"])
@admin_required
def admin_delete_submission(submission_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT report_file FROM phase2_inputs WHERE id=%s", (submission_id,))
    row = cur.fetchone()
    if row and row[0]:
        file_path = os.path.join(os.getcwd(), "reports", os.path.basename(row[0]))
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass
    cur.execute("DELETE FROM phase2_inputs WHERE id=%s", (submission_id,))
    conn.commit()
    cur.close()
    conn.close()
    flash("Submission deleted", "success")
    return redirect(url_for("admin_reports"))

# ---------------------------
# ADMIN: REGENERATE REPORT
# ---------------------------
@app.route("/admin/regenerate_report/<int:report_id>", methods=["POST"])
@admin_required
def regenerate_report(report_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM phase2_inputs WHERE id=%s", (report_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        flash("Report not found", "danger")
        return redirect(url_for("admin_reports"))

    # map column names to values — use RealDictCursor if you need column names; here we re-query with RealDictCursor
    cur.close(); conn.close()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM phase2_inputs WHERE id=%s", (report_id,))
    data = cur.fetchone()
    cur.close()
    conn.close()

    # Prepare inputs for AI call
    ai_input_data = {k: data.get(k, '') for k in data.keys() if k not in ['id', 'created_at', 'report_file']}

    # Run Validation first
    from logic.validation import validate_app_idea
    is_valid, reason = validate_app_idea(ai_input_data)

    if not is_valid:
        flash(f"❌ Cannot regenerate: Submission data failed validation: {reason}", "danger")
        return redirect(url_for("admin_reports"))

    # Call AI
    try:
        ai_result = call_gemini(ai_input_data)
    except Exception as e:
        print("Gemini call error during regeneration:", e)
        flash("⚠️ AI failed to respond during regeneration.", "warning")
        ai_result = {"verdict": "Error", "ai_score": None, "suggestions": [], "summary": {}}

    # Generate filename & PDF
    safe_user = (data.get("submitter_email") or data.get("user_email") or "user").split("@")[0]
    file_name = f"report_{safe_user}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    file_path = os.path.join("reports", file_name)

    if generate_pdf:
        try:
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
        except Exception as e:
            print("PDF regeneration error:", e)
            flash("⚠️ PDF generation failed during regeneration.", "warning")

    # Save updates
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE phase2_inputs
        SET ai_verdict=%s, ai_score=%s, ai_suggestions=%s, ai_summary=%s, report_file=%s, created_at=%s
        WHERE id=%s
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
    cur.close()
    conn.close()

    flash("✅ Report regenerated successfully!", "success")
    return redirect(url_for("admin_report_detail", report_id=report_id))

# Admin - update user
@app.route("/admin/update_user", methods=["POST"])
@admin_required
def admin_update_user():
    user_id = request.form.get("id")
    name = request.form.get("name")
    phone = request.form.get("phone")
    address = request.form.get("address")
    role = request.form.get("role", "user")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET name = %s, phone = %s, address = %s, role = %s
        WHERE id = %s
    """, (name, phone, address, role, user_id))
    conn.commit()
    cur.close()
    conn.close()
    flash("User updated", "success")
    return redirect(url_for("admin_users"))

# Admin - View Single Report Detail
@app.route("/admin/report_detail/<int:report_id>")
@admin_required
def admin_report_detail(report_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM phase2_inputs WHERE id=%s", (report_id,))
    report = cur.fetchone()
    cur.close()
    conn.close()

    if not report:
        flash("Report not found.", "danger")
        return redirect(url_for("admin_reports"))

    # Parse JSON fields
    try:
        summary = json.loads(report["ai_summary"]) if report.get("ai_summary") else {}
    except (json.JSONDecodeError, TypeError):
        summary = {"Summary Error": "Could not parse AI Summary."}

    try:
        suggestions = json.loads(report["ai_suggestions"]) if report.get("ai_suggestions") else []
    except (json.JSONDecodeError, TypeError):
        suggestions = []

    # Get all columns for display
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'phase2_inputs'
        ORDER BY ordinal_position
    """)
    cols = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()

    display_inputs = {}
    for col in cols:
        if col not in ["id", "user_email", "complexity_score", "financial_score", "ai_verdict", "ai_score", "ai_suggestions", "ai_summary", "report_file", "created_at"]:
            display_inputs[col.replace('_', ' ').title()] = report.get(col)

    return render_template("admin_report_detail.html",
                           report=report,
                           summary=summary,
                           suggestions=suggestions,
                           inputs=display_inputs,
                           title=f"Admin: Report #{report_id}")

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
        selected_features = request.form.getlist('must_have_features_list')
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

        # persist submission — use RETURNING id to capture submission_id
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''INSERT INTO phase2_inputs (
            user_email, core_problem_statement, user_role_segment, monetization_model,
            current_solution_inefficiency, unique_value_proposition, primary_competitors_text,
            must_have_features_list, arpu_estimate_usd, acquisition_goal_3mo,
            monthly_opex_est_usd, dev_budget_range, external_integrations_list,
            client_post_launch_fear, client_critical_question,
            complexity_score, financial_score,
            target_countries, submitter_name, submitter_email, submitter_phone, created_at
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id
        ''', (
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
            session.get('submitter_phone'),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        submission_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        # Prepare user inputs dict
        user_inputs = {k: session.get(k, '') for k in [
            "core_problem_statement", "user_role_segment", "monetization_model",
            "current_solution_inefficiency", "unique_value_proposition", "primary_competitors_text",
            "must_have_features_list", "arpu_estimate_usd", "acquisition_goal_3mo",
            "monthly_opex_est_usd", "external_integrations_list",
            "client_post_launch_fear", "client_critical_question"
        ]}

        # Validate
        from logic.validation import validate_app_idea
        is_valid, reason = validate_app_idea(user_inputs)
        if not is_valid:
            # Update DB with error status
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('UPDATE phase2_inputs SET ai_verdict=%s, created_at=%s WHERE id=%s',
                        ("❌ Invalid Submission", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), submission_id))
            conn.commit()
            cur.close()
            conn.close()
            # Keep login info only
            keep = {k: session.get(k) for k in ["user_email", "role", "user_name", "user_picture"]}
            session.clear()
            session.update({k: v for k, v in keep.items() if v})
            return render_template(
                'result.html',
                verdict="❌ Invalid Submission",
                ai_score=0,
                summary={"error": reason},
                suggestions=[]
            )

        # Call Gemini AI
        try:
            ai_result = call_gemini(user_inputs)
        except Exception as e:
            print("Gemini call error:", e)
            ai_result = {"verdict": "Error", "ai_score": None, "suggestions": [], "summary": {}}

        # Generate PDF & save
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
            try:
                with open(file_path, "wb") as f:
                    f.write(b"")
            except Exception:
                pass

        # Update DB with AI results
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            UPDATE phase2_inputs
            SET ai_verdict=%s, ai_score=%s, ai_suggestions=%s, ai_summary=%s, report_file=%s, created_at=%s
            WHERE id=%s
        ''', (
            ai_result.get("verdict"),
            ai_result.get("ai_score"),
            json.dumps(ai_result.get("suggestions", [])),
            json.dumps(ai_result.get("summary", {})),
            file_name,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            submission_id
        ))
        conn.commit()
        cur.close()
        conn.close()

        # Keep login session
        keep = {k: session.get(k) for k in ["user_email", "role", "user_name", "user_picture"]}
        session.clear()
        session.update({k: v for k, v in keep.items() if v})

        # Render results
        return render_template('result.html',
                               verdict=ai_result.get("verdict"),
                               ai_score=ai_result.get("ai_score"),
                               suggestions=ai_result.get("suggestions", []),
                               summary=ai_result.get("summary", {}))

    # GET — prefill
    default_name = session.get("user_name", "")
    default_email = session.get("user_email", "")
    return render_template('step3.html',
                           active_step=3,
                           show_stepper=True,
                           default_name=default_name,
                           default_email=default_email)

# ---------- Reports (user) ----------
@app.route("/reports")
@login_required
def reports():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""SELECT id, ai_verdict, ai_score, report_file, created_at, core_problem_statement
                   FROM phase2_inputs
                   WHERE submitter_email = %s OR user_email = %s
                   ORDER BY id DESC""", (session.get("user_email"), session.get("user_email")))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    reports_data = []
    for r in rows:
        created = r[4]
        created_fmt = created.split('.')[0] if created else "N/A"
        reports_data.append({
            "id": r[0],
            "ai_verdict": r[1],
            "ai_score": r[2],
            "report_file": r[3],
            "created_at": created_fmt,
            "core_problem_statement": r[5]
        })
    return render_template("reports.html", reports=reports_data, title="My Reports")

# User - View Single Report Detail
@app.route("/report/<int:report_id>")
@login_required
def report_detail(report_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM phase2_inputs WHERE id=%s AND (user_email=%s OR submitter_email=%s)",
                (report_id, session.get("user_email"), session.get("user_email")))
    report = cur.fetchone()
    cur.close()
    conn.close()

    if not report:
        flash("Report not found or unauthorized.", "danger")
        return redirect(url_for("reports"))

    # Parse JSON fields
    try:
        summary = json.loads(report.get("ai_summary") or "{}")
    except Exception:
        summary = {"Summary Error": "Could not parse AI Summary."}
    try:
        suggestions = json.loads(report.get("ai_suggestions") or "[]")
    except Exception:
        suggestions = []

    # Get columns for display
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'phase2_inputs'
        ORDER BY ordinal_position
    """)
    cols = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()

    display_inputs = {}
    for col in cols:
        if col not in ["id", "user_email", "complexity_score", "financial_score", "ai_verdict", "ai_score", "ai_suggestions", "ai_summary", "report_file", "created_at"]:
            display_inputs[col.replace('_', ' ').title()] = report.get(col)

    return render_template("report_detail.html",
                           report=report,
                           summary=summary,
                           suggestions=suggestions,
                           inputs=display_inputs,
                           title=f"Report #{report_id} Detail")

# ---------- Secure Report Download ----------
@app.route("/download_report/<path:filename>")
@login_required
def download_report(filename):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM phase2_inputs WHERE report_file=%s AND (user_email=%s OR submitter_email=%s)",
                (filename, session.get("user_email"), session.get("user_email")))
    is_user_report = cur.fetchone()
    cur.close()
    conn.close()

    if is_user_report or session.get("role") == "admin":
        safe_filename = os.path.basename(filename)
        file_path = os.path.join(os.getcwd(), "reports", safe_filename)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True, download_name=safe_filename)
        else:
            flash(f"Report file '{safe_filename}' not found on server.", "danger")
            return redirect(url_for("reports"))
    else:
        flash("You are not authorized to download this report.", "danger")
        return redirect(url_for("reports"))

# ---------- Dev: reset DB (admin only) ----------
@app.route("/reset-db")
@admin_required
def reset_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS phase2_inputs")
    conn.commit()
    cur.close()
    conn.close()
    init_db()
    flash("Database reset and migrated.", "success")
    return redirect(url_for("admin_dashboard"))

# ---------- Run (local dev) ----------
if __name__ == '__main__':
    # Optionally insert dummy data if table is empty (useful for local testing)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM phase2_inputs")
    count = cur.fetchone()[0]
    if count == 0:
        try:
            from logic.dummy_data import insert_dummy_data
            insert_dummy_data(conn)  # note: your dummy helper must work with psycopg2 connection
            print("✅ Inserted dummy data for testing.")
        except Exception:
            print("⚠️ Could not insert dummy data. Continue without it.")
    cur.close()
    conn.close()
    app.run(debug=True)
