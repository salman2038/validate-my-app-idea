from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3, os, json
from dotenv import load_dotenv
from datetime import datetime
from functools import wraps

# Ensure the reports directory exists
os.makedirs("reports", exist_ok=True)

# Your project logic utilities (must exist)
from logic.score_engine import calculate_complexity, calculate_financial_viability
from logic.gemini_api import call_gemini

# Optional PDF generator helpers you wrote
# logic/pdf_generator.py should provide generate_pdf(...) or generate_pdf_report(...)
try:
    from logic.pdf_generator import generate_pdf_report, generate_pdf
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
# DB_NAME = "datarector.db"
import os

# Create persistent data folder if it doesn’t exist
os.makedirs("/opt/render/project/src/data", exist_ok=True)

# Persistent SQLite path on Render
DB_NAME = "/opt/render/project/src/data/app_database.sqlite3"
REPORTS_DIR = "/opt/render/project/src/data/reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

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

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

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
    # Removed redundant imports; rely on global imports

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM phase2_inputs WHERE id=?", (report_id,))
    row = c.fetchone()
    if not row:
        flash("Report not found", "danger")
        return redirect(url_for("admin_reports"))

    # Convert row tuple to dictionary
    cols = [d[0] for d in c.description]
    data = dict(zip(cols, row))
    conn.close() # Close DB connection early

    # Prepare inputs for AI call
    ai_input_data = {k: data.get(k, '') for k in data if k not in ['id', 'created_at', 'report_file']}
    
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

    # Correct consistent filename
    safe_user = (data.get("submitter_email") or data.get("user_email") or "user").split("@")[0]
    file_name = f"report_{safe_user}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    file_path = os.path.join("reports", file_name)

    # Generate PDF and save in reports folder
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


    # Save only filename (not full path)
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

# Admin - View Single Report Detail
@app.route("/admin/report_detail/<int:report_id>")
@admin_required
def admin_report_detail(report_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM phase2_inputs WHERE id=?", (report_id,))
    report = c.fetchone()
    conn.close()

    if not report:
        flash("Report not found.", "danger")
        return redirect(url_for("admin_reports"))
    
    # Convert complex JSON fields back to Python objects
    try:
        summary = json.loads(report["ai_summary"])
    except (json.JSONDecodeError, TypeError):
        summary = {"Summary Error": "Could not parse AI Summary."}
    
    try:
        suggestions = json.loads(report["ai_suggestions"])
    except (json.JSONDecodeError, TypeError):
        suggestions = []

    # Get the original column names for displaying input fields
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("PRAGMA table_info(phase2_inputs)")
    cols = [r[1] for r in c.fetchall()]
    conn.close()

    # Filter inputs for display
    display_inputs = {}
    for col in cols:
        # Exclude internal/output fields
        if col not in ["id", "user_email", "complexity_score", "financial_score", "ai_verdict", "ai_score", "ai_suggestions", "ai_summary", "report_file", "created_at"]:
             display_inputs[col.replace('_', ' ').title()] = report[col]

    return render_template("admin_report_detail.html", 
                           report=report, 
                           summary=summary,
                           suggestions=suggestions,
                           inputs=display_inputs,
                           title=f"Admin: Report #{report_id}")

# ---------- Multi-step form routes ----------
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
        # Capture custom text inputs for User Roles and Monetization
        custom_user_role = request.form.get('user_role_segment_other', '').strip()
        custom_money_model = request.form.get('monetization_model_other', '').strip()
        
        # Get all selected list values (which may include 'Other_User' or 'Other_Money' placeholders)
        selected_user_roles = request.form.getlist('user_role_segment')
        selected_money_models = request.form.getlist('monetization_model')
        
        final_user_roles = []
        final_money_models = []

        # 1. Process User Roles
        if 'Other_User' in selected_user_roles and custom_user_role:
            # If 'Other_User' was selected AND custom text was provided, add the custom text
            selected_user_roles.remove('Other_User')
            selected_user_roles.append(custom_user_role)
        
        # Filter out the placeholder itself if it was selected but no custom text was entered
        final_user_roles = [role for role in selected_user_roles if role != 'Other_User']
        
        # 2. Process Monetization Models
        if 'Other_Money' in selected_money_models and custom_money_model:
            # If 'Other_Money' was selected AND custom text was provided, add the custom text
            selected_money_models.remove('Other_Money')
            selected_money_models.append(custom_money_model)
        
        # Filter out the placeholder itself if it was selected but no custom text was entered
        final_money_models = [model for model in selected_money_models if model != 'Other_Money']


        # Update session with processed, combined lists
        session['core_problem_statement'] = request.form.get('core_problem_statement', '')
        session['user_role_segment'] = ', '.join(final_user_roles)
        session['monetization_model'] = ', '.join(final_money_models)

        # Validation Check
        if not session['core_problem_statement'] or not session['user_role_segment'] or not session['monetization_model']:
            return render_template('step1.html', error="Please fill all required fields before continuing.",
                                   core_problem_statement=session.get('core_problem_statement', ''),
                                   # Pass back current values to repopulate form fields (including custom text if needed)
                                   user_role_segment=session.get('user_role_segment', ''),
                                   monetization_model=session.get('monetization_model', ''),
                                   active_step=1, show_stepper=True)
        return redirect(url_for("step2"))
        
    # GET logic remains the same
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

import time

@app.route("/step3", methods=["GET", "POST"])
@login_required
def step3():
    from logic.validation import validate_app_idea
    from logic.pdf_generator import generate_pdf
    import time

    if request.method == "POST":
        # --- Collect personal details ---
        session['submitter_name'] = request.form.get('user_name', '')
        session['submitter_email'] = request.form.get('user_email', '')
        session['submitter_phone'] = request.form.get('user_phone', '')

        # --- Financial details ---
        session['arpu_estimate_usd'] = request.form.get('arpu_estimate_usd', '')
        session['acquisition_goal_3mo'] = request.form.get('acquisition_goal_3mo', '')
        session['monthly_opex_est_usd'] = request.form.get('monthly_opex_est_usd', '')
        session['dev_budget_range'] = request.form.get('dev_budget_range', '')
        session['external_integrations_list'] = ', '.join(request.form.getlist('external_integrations_list'))
        session['client_post_launch_fear'] = request.form.get('client_post_launch_fear', '')
        session['client_critical_question'] = request.form.get('client_critical_question', '')

        # --- Validate required fields ---
        if not session['arpu_estimate_usd'] or not session['acquisition_goal_3mo'] or not session['monthly_opex_est_usd']:
            return render_template(
                'step3.html',
                error="Please complete all required fields before submitting.",
                active_step=3,
                show_stepper=True
            )

        # --- Compute local scores ---
        complexity_score = calculate_complexity(
            session.get('must_have_features_list', ''),
            session.get('external_integrations_list', '')
        )
        financial_score = calculate_financial_viability(
            session.get('arpu_estimate_usd', ''),
            session.get('acquisition_goal_3mo', ''),
            session.get('monthly_opex_est_usd', '')
        )

        # --- Save initial record to DB ---
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
        submission_id = c.lastrowid
        conn.commit()
        conn.close()

        # --- Prepare inputs for Gemini ---
        user_inputs = {k: session.get(k, '') for k in [
            "core_problem_statement", "user_role_segment", "monetization_model",
            "current_solution_inefficiency", "unique_value_proposition", "primary_competitors_text",
            "must_have_features_list", "arpu_estimate_usd", "acquisition_goal_3mo",
            "monthly_opex_est_usd", "external_integrations_list",
            "client_post_launch_fear", "client_critical_question"
        ]}

        # --- Local validation ---
        is_valid, reason = validate_app_idea(user_inputs)
        if not is_valid:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute(
                'UPDATE phase2_inputs SET ai_verdict=?, created_at=? WHERE id=?',
                ("❌ Invalid Submission", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), submission_id)
            )
            conn.commit()
            conn.close()
            return render_template("result.html",
                                   verdict="❌ Invalid Submission",
                                   ai_score=0,
                                   summary={"error": reason},
                                   suggestions=[])

        # --- Call Gemini API safely ---
        from logic.gemini_api import call_gemini
        ai_result = None
        for attempt in range(3):
            try:
                ai_result = call_gemini(user_inputs)
                if ai_result and "error" not in ai_result:
                    break
                print(f"⚠️ Gemini attempt {attempt + 1} failed: {ai_result.get('error')}")
            except Exception as e:
                print(f"⚠️ Gemini attempt {attempt + 1} raised: {e}")
            time.sleep(1)

        if not ai_result or "error" in ai_result:
            ai_result = {
                "verdict": "Error",
                "ai_score": 0,
                "suggestions": ["AI model was unavailable. Please try again later."],
                "summary": {"error": "Gemini API unavailable"}
            }

        # --- Generate PDF (always in /data/reports) ---
        try:
            pdf_path = generate_pdf({
                "user_email": session.get("submitter_email") or session.get("user_email"),
                "verdict": ai_result.get("verdict"),
                "ai_score": ai_result.get("ai_score"),
                "summary": ai_result.get("summary", {}),
                "suggestions": ai_result.get("suggestions", [])
            })
            file_name = os.path.basename(pdf_path)
        except Exception as e:
            print("⚠️ PDF generation failed:", e)
            file_name = None

        # --- Update DB with AI + PDF info ---
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            UPDATE phase2_inputs
            SET ai_verdict=?, ai_score=?, ai_suggestions=?, ai_summary=?, report_file=?, created_at=?
            WHERE id=?
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
        conn.close()

        # ✅ Return result page
        return render_template(
            "result.html",
            verdict=ai_result.get("verdict", "Unknown"),
            ai_score=ai_result.get("ai_score", 0),
            summary=ai_result.get("summary", {}),
            suggestions=ai_result.get("suggestions", []),
        )

    # --- GET: Render Step 3 form ---
    return render_template(
        "step3.html",
        active_step=3,
        show_stepper=True,
        default_name=session.get("user_name", ""),
        default_email=session.get("user_email", "")
    )

@app.route("/reports")
@login_required
def reports():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        SELECT id, ai_verdict, ai_score, report_file, created_at, core_problem_statement
        FROM phase2_inputs
        WHERE submitter_email = ? OR user_email = ?
        ORDER BY id DESC
    """, (session.get("user_email"), session.get("user_email")))
    rows = c.fetchall()
    conn.close()

    reports_data = []
    for r in rows:
        reports_data.append({
            "id": r[0],
            "ai_verdict": r[1],
            "ai_score": r[2],
            "report_file": r[3],
            "created_at": r[4].split('.')[0] if r[4] else "N/A",
            "core_problem_statement": r[5]
        })

    return render_template("reports.html", reports=reports_data, title="My Reports")

# ---------- Secure Report Download ----------
# ---------- Secure Report Download (robust & simplified) ----------
@app.route("/download_report/<path:filename>")
@login_required
def download_report(filename):
    import os
    safe_filename = os.path.basename(filename)
    user_email = session.get("user_email")

    # 1️⃣ Verify report ownership
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        SELECT id FROM phase2_inputs 
        WHERE report_file=? AND (user_email=? OR submitter_email=?)
    """, (safe_filename, user_email, user_email))
    is_user_report = c.fetchone()
    conn.close()

    if not (is_user_report or session.get("role") == "admin"):
        flash("🚫 You are not authorized to download this report.", "danger")
        return redirect(url_for("reports"))

    # 2️⃣ Check correct locations
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidate_paths = [
        os.path.join(base_dir, "data", "reports", safe_filename),  # ✅ persistent
        os.path.join(base_dir, "reports", safe_filename),          # fallback
    ]

    for path in candidate_paths:
        if os.path.exists(path):
            print(f"✅ Sending file: {path}")
            return send_file(path, as_attachment=True, download_name=safe_filename)

    flash(f"❌ Report file '{safe_filename}' not found on server.", "danger")
    return redirect(url_for("reports"))
        
@app.route("/debug_list_reports")
def debug_list_reports():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(base_dir, "data", "reports")
    if not os.path.exists(reports_dir):
        return f"❌ Folder not found: {reports_dir}"
    files = os.listdir(reports_dir)
    return f"📁 Found {len(files)} files:<br>" + "<br>".join(files)

# ---------- Admin: View All Submissions ----------
@app.route("/admin/submissions")
@login_required
def admin_submissions():
    if session.get("role") != "admin":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("dashboard"))

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT id, submitter_name, submitter_email, user_email,
               core_problem_statement, monetization_model,
               ai_verdict, ai_score, created_at
        FROM phase2_inputs
        ORDER BY id DESC
    """)
    rows = c.fetchall()
    conn.close()

    return render_template("admin_submissions.html", submissions=rows, title="All User Submissions")

if __name__ == '__main__':
    # Add dummy inputs for testing purposes if the database is empty
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM phase2_inputs")
    if c.fetchone()[0] == 0:
        try:
             from logic.dummy_data import insert_dummy_data
             insert_dummy_data(conn)
             print("✅ Inserted dummy data for testing.")
        except ImportError:
            print("⚠️ Could not import logic.dummy_data. Run the app without dummy data.")
    conn.close()
    # Run the application
    app.run(debug=True)