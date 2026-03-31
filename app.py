import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE  = os.path.join(BASE_DIR, 'placement.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

app = Flask(__name__)
app.secret_key = 'placement_portal_secret_key_2024'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur.lastrowid

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ─────────────────────────────────────────────────────────────────────────────
# Database Initialisation
# ─────────────────────────────────────────────────────────────────────────────
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS admin (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                name     TEXT    NOT NULL,
                email    TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS students (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT    NOT NULL,
                email           TEXT    NOT NULL UNIQUE,
                password        TEXT    NOT NULL,
                phone           TEXT,
                resume_filename TEXT,
                is_active       INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS companies (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                email       TEXT    NOT NULL UNIQUE,
                password    TEXT    NOT NULL,
                website     TEXT,
                hr_contact  TEXT,
                is_approved INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS placement_drives (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id  INTEGER NOT NULL,
                job_title   TEXT    NOT NULL,
                job_desc    TEXT    NOT NULL,
                eligibility TEXT    NOT NULL,
                deadline    TEXT    NOT NULL,
                status      TEXT    NOT NULL DEFAULT 'Pending',
                created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS applications (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id   INTEGER NOT NULL,
                drive_id     INTEGER NOT NULL,
                applied_date TEXT    NOT NULL DEFAULT (datetime('now')),
                status       TEXT    NOT NULL DEFAULT 'Applied',
                FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
                FOREIGN KEY (drive_id)   REFERENCES placement_drives(id) ON DELETE CASCADE,
                UNIQUE (student_id, drive_id)
            );
        """)

        # Seed default admin if not present
        admin = conn.execute("SELECT id FROM admin WHERE email = ?",
                             ('admin@placement.com',)).fetchone()
        if not admin:
            hashed = generate_password_hash('admin123')
            conn.execute(
                "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
                ('Admin', 'admin@placement.com', hashed)
            )
        conn.commit()

# ─────────────────────────────────────────────────────────────────────────────
# Auth decorators
# ─────────────────────────────────────────────────────────────────────────────
def login_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get('role') != role:
                flash('Please log in to access that page.', 'warning')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated
    return decorator

login_required_admin   = login_required('admin')
login_required_company = login_required('company')
login_required_student = login_required('student')

# ─────────────────────────────────────────────────────────────────────────────
# Context processors
# ─────────────────────────────────────────────────────────────────────────────
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# ─────────────────────────────────────────────────────────────────────────────
# ── AUTHENTICATION ROUTES ──────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    if session.get('role') == 'company':
        return redirect(url_for('company_dashboard'))
    if session.get('role') == 'student':
        return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', '')

        if role == 'admin':
            user = query_db("SELECT * FROM admin WHERE email = ?", [email], one=True)
            if user and check_password_hash(user['password'], password):
                session['role'] = 'admin'
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                flash('Welcome back, Admin!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid admin credentials.', 'danger')

        elif role == 'company':
            user = query_db("SELECT * FROM companies WHERE email = ?", [email], one=True)
            if user and check_password_hash(user['password'], password):
                if not user['is_approved']:
                    flash('Your company account is pending admin approval.', 'warning')
                else:
                    session['role'] = 'company'
                    session['user_id'] = user['id']
                    session['user_name'] = user['name']
                    flash(f'Welcome, {user["name"]}!', 'success')
                    return redirect(url_for('company_dashboard'))
            else:
                flash('Invalid company credentials.', 'danger')

        elif role == 'student':
            user = query_db("SELECT * FROM students WHERE email = ?", [email], one=True)
            if user and check_password_hash(user['password'], password):
                session['role'] = 'student'
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                flash(f'Welcome, {user["name"]}!', 'success')
                return redirect(url_for('student_dashboard'))
            else:
                flash('Invalid student credentials.', 'danger')
        else:
            flash('Please select a valid role.', 'danger')

    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        name  = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        pwd   = request.form.get('password', '')
        pwd2  = request.form.get('confirm_password', '')

        if not all([name, email, pwd]):
            flash('Name, email and password are required.', 'danger')
        elif pwd != pwd2:
            flash('Passwords do not match.', 'danger')
        elif query_db("SELECT id FROM students WHERE email = ?", [email], one=True):
            flash('Email already registered.', 'danger')
        else:
            hashed = generate_password_hash(pwd)
            resume_filename = None
            file = request.files.get('resume')
            if file and file.filename and allowed_file(file.filename):
                resume_filename = secure_filename(f"resume_{email}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], resume_filename))

            execute_db(
                "INSERT INTO students (name, email, password, phone, resume_filename) VALUES (?,?,?,?,?)",
                [name, email, hashed, phone, resume_filename]
            )
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('auth/student_register.html')

@app.route('/company/register', methods=['GET', 'POST'])
def company_register():
    if request.method == 'POST':
        name       = request.form.get('name', '').strip()
        email      = request.form.get('email', '').strip()
        pwd        = request.form.get('password', '')
        pwd2       = request.form.get('confirm_password', '')
        website    = request.form.get('website', '').strip()
        hr_contact = request.form.get('hr_contact', '').strip()

        if not all([name, email, pwd]):
            flash('Company name, email and password are required.', 'danger')
        elif pwd != pwd2:
            flash('Passwords do not match.', 'danger')
        elif query_db("SELECT id FROM companies WHERE email = ?", [email], one=True):
            flash('Email already registered.', 'danger')
        else:
            hashed = generate_password_hash(pwd)
            execute_db(
                "INSERT INTO companies (name, email, password, website, hr_contact) VALUES (?,?,?,?,?)",
                [name, email, hashed, website, hr_contact]
            )
            flash('Registration successful! Please wait for admin approval.', 'success')
            return redirect(url_for('login'))
    return render_template('auth/company_register.html')

# ─────────────────────────────────────────────────────────────────────────────
# ── ADMIN ROUTES ──────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/admin/dashboard')
@login_required_admin
def admin_dashboard():
    stats = {
        'students':    query_db("SELECT COUNT(*) as c FROM students",          one=True)['c'],
        'companies':   query_db("SELECT COUNT(*) as c FROM companies",         one=True)['c'],
        'drives':      query_db("SELECT COUNT(*) as c FROM placement_drives",  one=True)['c'],
        'applications':query_db("SELECT COUNT(*) as c FROM applications",      one=True)['c'],
    }
    students  = query_db("SELECT * FROM students  ORDER BY created_at DESC LIMIT 5")
    companies = query_db("SELECT * FROM companies ORDER BY created_at DESC LIMIT 5")
    drives    = query_db("""
        SELECT pd.*, c.name AS company_name
        FROM placement_drives pd JOIN companies c ON pd.company_id = c.id
        ORDER BY pd.created_at DESC LIMIT 5
    """)
    applications = query_db("""
        SELECT a.*, s.name AS student_name, pd.job_title, c.name AS company_name
        FROM applications a
        JOIN students s ON a.student_id = s.id
        JOIN placement_drives pd ON a.drive_id = pd.id
        JOIN companies c ON pd.company_id = c.id
        ORDER BY a.applied_date DESC LIMIT 5
    """)
    return render_template('admin/dashboard.html', stats=stats,
                           students=students, companies=companies,
                           drives=drives, applications=applications)

# -- Students management
@app.route('/admin/students')
@login_required_admin
def admin_students():
    q = request.args.get('q', '').strip()
    if q:
        students = query_db(
            "SELECT * FROM students WHERE name LIKE ? OR email LIKE ? OR CAST(id AS TEXT) LIKE ? ORDER BY created_at DESC",
            [f'%{q}%', f'%{q}%', f'%{q}%']
        )
    else:
        students = query_db("SELECT * FROM students ORDER BY created_at DESC")
    return render_template('admin/students.html', students=students, q=q)

@app.route('/admin/students/edit/<int:sid>', methods=['GET', 'POST'])
@login_required_admin
def admin_edit_student(sid):
    student = query_db("SELECT * FROM students WHERE id = ?", [sid], one=True)
    if not student:
        flash('Student not found.', 'danger')
        return redirect(url_for('admin_students'))
    if request.method == 'POST':
        name  = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        execute_db("UPDATE students SET name=?, email=?, phone=? WHERE id=?",
                   [name, email, phone, sid])
        flash('Student updated.', 'success')
        return redirect(url_for('admin_students'))
    return render_template('admin/edit_student.html', student=student)

@app.route('/admin/students/delete/<int:sid>', methods=['POST'])
@login_required_admin
def admin_delete_student(sid):
    execute_db("DELETE FROM students WHERE id = ?", [sid])
    flash('Student deleted.', 'success')
    return redirect(url_for('admin_students'))

# -- Companies management
@app.route('/admin/companies')
@login_required_admin
def admin_companies():
    q = request.args.get('q', '').strip()
    if q:
        companies = query_db(
            "SELECT * FROM companies WHERE name LIKE ? OR email LIKE ? ORDER BY created_at DESC",
            [f'%{q}%', f'%{q}%']
        )
    else:
        companies = query_db("SELECT * FROM companies ORDER BY created_at DESC")
    return render_template('admin/companies.html', companies=companies, q=q)

@app.route('/admin/companies/approve/<int:cid>', methods=['POST'])
@login_required_admin
def admin_approve_company(cid):
    execute_db("UPDATE companies SET is_approved = 1 WHERE id = ?", [cid])
    flash('Company approved.', 'success')
    return redirect(url_for('admin_companies'))

@app.route('/admin/companies/reject/<int:cid>', methods=['POST'])
@login_required_admin
def admin_reject_company(cid):
    execute_db("UPDATE companies SET is_approved = 0 WHERE id = ?", [cid])
    flash('Company rejected.', 'warning')
    return redirect(url_for('admin_companies'))

@app.route('/admin/companies/edit/<int:cid>', methods=['GET', 'POST'])
@login_required_admin
def admin_edit_company(cid):
    company = query_db("SELECT * FROM companies WHERE id = ?", [cid], one=True)
    if not company:
        flash('Company not found.', 'danger')
        return redirect(url_for('admin_companies'))
    if request.method == 'POST':
        name       = request.form.get('name', '').strip()
        email      = request.form.get('email', '').strip()
        website    = request.form.get('website', '').strip()
        hr_contact = request.form.get('hr_contact', '').strip()
        execute_db("UPDATE companies SET name=?, email=?, website=?, hr_contact=? WHERE id=?",
                   [name, email, website, hr_contact, cid])
        flash('Company updated.', 'success')
        return redirect(url_for('admin_companies'))
    return render_template('admin/edit_company.html', company=company)

@app.route('/admin/companies/delete/<int:cid>', methods=['POST'])
@login_required_admin
def admin_delete_company(cid):
    execute_db("DELETE FROM companies WHERE id = ?", [cid])
    flash('Company deleted.', 'success')
    return redirect(url_for('admin_companies'))

# -- Drives management
@app.route('/admin/drives')
@login_required_admin
def admin_drives():
    drives = query_db("""
        SELECT pd.*, c.name AS company_name,
               (SELECT COUNT(*) FROM applications a WHERE a.drive_id = pd.id) AS app_count
        FROM placement_drives pd JOIN companies c ON pd.company_id = c.id
        ORDER BY pd.created_at DESC
    """)
    return render_template('admin/drives.html', drives=drives)

@app.route('/admin/drives/approve/<int:did>', methods=['POST'])
@login_required_admin
def admin_approve_drive(did):
    execute_db("UPDATE placement_drives SET status = 'Approved' WHERE id = ?", [did])
    flash('Drive approved.', 'success')
    return redirect(url_for('admin_drives'))

@app.route('/admin/drives/reject/<int:did>', methods=['POST'])
@login_required_admin
def admin_reject_drive(did):
    execute_db("UPDATE placement_drives SET status = 'Pending' WHERE id = ?", [did])
    flash('Drive rejected / set back to Pending.', 'warning')
    return redirect(url_for('admin_drives'))

@app.route('/admin/drives/delete/<int:did>', methods=['POST'])
@login_required_admin
def admin_delete_drive(did):
    execute_db("DELETE FROM placement_drives WHERE id = ?", [did])
    flash('Drive deleted.', 'success')
    return redirect(url_for('admin_drives'))

# -- Applications overview
@app.route('/admin/applications')
@login_required_admin
def admin_applications():
    applications = query_db("""
        SELECT a.*, s.name AS student_name, s.email AS student_email,
               pd.job_title, c.name AS company_name
        FROM applications a
        JOIN students s ON a.student_id = s.id
        JOIN placement_drives pd ON a.drive_id = pd.id
        JOIN companies c ON pd.company_id = c.id
        ORDER BY a.applied_date DESC
    """)
    return render_template('admin/applications.html', applications=applications)

# ─────────────────────────────────────────────────────────────────────────────
# ── COMPANY ROUTES ─────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/company/dashboard')
@login_required_company
def company_dashboard():
    cid = session['user_id']
    company = query_db("SELECT * FROM companies WHERE id = ?", [cid], one=True)
    drives  = query_db("""
        SELECT pd.*,
               (SELECT COUNT(*) FROM applications a WHERE a.drive_id = pd.id) AS app_count
        FROM placement_drives pd WHERE pd.company_id = ?
        ORDER BY pd.created_at DESC
    """, [cid])
    return render_template('company/dashboard.html', company=company, drives=drives)

@app.route('/company/drives/create', methods=['GET', 'POST'])
@login_required_company
def company_create_drive():
    if request.method == 'POST':
        job_title   = request.form.get('job_title', '').strip()
        job_desc    = request.form.get('job_desc', '').strip()
        eligibility = request.form.get('eligibility', '').strip()
        deadline    = request.form.get('deadline', '').strip()
        if not all([job_title, job_desc, eligibility, deadline]):
            flash('All fields are required.', 'danger')
        else:
            execute_db(
                "INSERT INTO placement_drives (company_id, job_title, job_desc, eligibility, deadline) VALUES (?,?,?,?,?)",
                [session['user_id'], job_title, job_desc, eligibility, deadline]
            )
            flash('Drive created! Awaiting admin approval.', 'success')
            return redirect(url_for('company_dashboard'))
    return render_template('company/create_drive.html')

@app.route('/company/drives/edit/<int:did>', methods=['GET', 'POST'])
@login_required_company
def company_edit_drive(did):
    drive = query_db("SELECT * FROM placement_drives WHERE id = ? AND company_id = ?",
                     [did, session['user_id']], one=True)
    if not drive:
        flash('Drive not found.', 'danger')
        return redirect(url_for('company_dashboard'))
    if request.method == 'POST':
        job_title   = request.form.get('job_title', '').strip()
        job_desc    = request.form.get('job_desc', '').strip()
        eligibility = request.form.get('eligibility', '').strip()
        deadline    = request.form.get('deadline', '').strip()
        execute_db(
            "UPDATE placement_drives SET job_title=?, job_desc=?, eligibility=?, deadline=?, status='Pending' WHERE id=?",
            [job_title, job_desc, eligibility, deadline, did]
        )
        flash('Drive updated. It will need re-approval.', 'success')
        return redirect(url_for('company_dashboard'))
    return render_template('company/edit_drive.html', drive=drive)

@app.route('/company/drives/close/<int:did>', methods=['POST'])
@login_required_company
def company_close_drive(did):
    execute_db(
        "UPDATE placement_drives SET status='Closed' WHERE id = ? AND company_id = ?",
        [did, session['user_id']]
    )
    flash('Drive closed.', 'success')
    return redirect(url_for('company_dashboard'))

@app.route('/company/drives/delete/<int:did>', methods=['POST'])
@login_required_company
def company_delete_drive(did):
    execute_db(
        "DELETE FROM placement_drives WHERE id = ? AND company_id = ?",
        [did, session['user_id']]
    )
    flash('Drive deleted.', 'success')
    return redirect(url_for('company_dashboard'))

@app.route('/company/drives/<int:did>/applications')
@login_required_company
def company_drive_applications(did):
    drive = query_db("SELECT * FROM placement_drives WHERE id = ? AND company_id = ?",
                     [did, session['user_id']], one=True)
    if not drive:
        flash('Drive not found.', 'danger')
        return redirect(url_for('company_dashboard'))
    applications = query_db("""
        SELECT a.*, s.name AS student_name, s.email AS student_email,
               s.phone, s.resume_filename
        FROM applications a JOIN students s ON a.student_id = s.id
        WHERE a.drive_id = ?
        ORDER BY a.applied_date DESC
    """, [did])
    return render_template('company/applications.html',
                           drive=drive, applications=applications)

@app.route('/company/applications/update/<int:aid>', methods=['POST'])
@login_required_company
def company_update_application(aid):
    status = request.form.get('status', '')
    allowed = ['Applied', 'Shortlisted', 'Selected', 'Rejected']
    if status not in allowed:
        flash('Invalid status.', 'danger')
        return redirect(url_for('company_dashboard'))

    app_row = query_db("""
        SELECT a.*, pd.company_id FROM applications a
        JOIN placement_drives pd ON a.drive_id = pd.id
        WHERE a.id = ?
    """, [aid], one=True)

    if not app_row or app_row['company_id'] != session['user_id']:
        flash('Unauthorised.', 'danger')
        return redirect(url_for('company_dashboard'))

    execute_db("UPDATE applications SET status = ? WHERE id = ?", [status, aid])
    flash('Application status updated.', 'success')
    did = app_row['drive_id']
    return redirect(url_for('company_drive_applications', did=did))

# ─────────────────────────────────────────────────────────────────────────────
# ── STUDENT ROUTES ─────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/student/dashboard')
@login_required_student
def student_dashboard():
    sid = session['user_id']
    # Applied drive IDs
    applied_ids = {row['drive_id'] for row in
                   query_db("SELECT drive_id FROM applications WHERE student_id = ?", [sid])}
    # All approved drives
    drives = query_db("""
        SELECT pd.*, c.name AS company_name
        FROM placement_drives pd JOIN companies c ON pd.company_id = c.id
        WHERE pd.status = 'Approved'
        ORDER BY pd.deadline ASC
    """)
    # Student's applications with drive + company info
    my_apps = query_db("""
        SELECT a.*, pd.job_title, pd.deadline, c.name AS company_name
        FROM applications a
        JOIN placement_drives pd ON a.drive_id = pd.id
        JOIN companies c ON pd.company_id = c.id
        WHERE a.student_id = ?
        ORDER BY a.applied_date DESC
    """, [sid])
    return render_template('student/dashboard.html',
                           drives=drives, my_apps=my_apps, applied_ids=applied_ids)

@app.route('/student/drives/<int:did>')
@login_required_student
def student_view_drive(did):
    drive = query_db("""
        SELECT pd.*, c.name AS company_name, c.website, c.hr_contact
        FROM placement_drives pd JOIN companies c ON pd.company_id = c.id
        WHERE pd.id = ? AND pd.status = 'Approved'
    """, [did], one=True)
    if not drive:
        flash('Drive not found or not available.', 'danger')
        return redirect(url_for('student_dashboard'))
    already_applied = query_db(
        "SELECT id FROM applications WHERE student_id = ? AND drive_id = ?",
        [session['user_id'], did], one=True
    )
    return render_template('student/view_drive.html',
                           drive=drive, already_applied=already_applied)

@app.route('/student/drives/<int:did>/apply', methods=['POST'])
@login_required_student
def student_apply(did):
    sid = session['user_id']
    drive = query_db("SELECT * FROM placement_drives WHERE id = ? AND status = 'Approved'",
                     [did], one=True)
    if not drive:
        flash('Drive not available.', 'danger')
        return redirect(url_for('student_dashboard'))
    existing = query_db("SELECT id FROM applications WHERE student_id=? AND drive_id=?",
                        [sid, did], one=True)
    if existing:
        flash('You have already applied to this drive.', 'warning')
    else:
        execute_db("INSERT INTO applications (student_id, drive_id) VALUES (?,?)",
                   [sid, did])
        flash('Application submitted successfully!', 'success')
    return redirect(url_for('student_dashboard'))

@app.route('/student/profile', methods=['GET', 'POST'])
@login_required_student
def student_profile():
    sid = session['user_id']
    student = query_db("SELECT * FROM students WHERE id = ?", [sid], one=True)
    if request.method == 'POST':
        name  = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        resume_filename = student['resume_filename']

        file = request.files.get('resume')
        if file and file.filename and allowed_file(file.filename):
            resume_filename = secure_filename(f"resume_{sid}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], resume_filename))

        execute_db("UPDATE students SET name=?, phone=?, email=?, resume_filename=? WHERE id=?",
                   [name, phone, email, resume_filename, sid])
        session['user_name'] = name
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('student_profile'))
    return render_template('student/profile.html', student=student)

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
