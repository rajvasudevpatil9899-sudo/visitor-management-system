
import datetime
import os
from pathlib import Path
import smtplib
import ssl
from email.message import EmailMessage

from dotenv import load_dotenv

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from mysql.connector import Error

from db import get_db_connection

# Load administrator-configured SMTP settings from the project .env file.
# On hosted servers, environment variables can be configured directly instead.
load_dotenv(Path(__file__).resolve().parent / ".env")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-this-to-a-long-random-secret-key")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# ---------------------------------------------------------------------
# ROLE-BASED AUTHENTICATION
# One administrator is created through /setup-admin on first run.
# The administrator creates individual security guard accounts.
# ---------------------------------------------------------------------
def ensure_users_table():
    """Create the staff account table if it does not already exist."""
    conn = get_db_connection()
    if conn is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                full_name VARCHAR(120) NOT NULL,
                username VARCHAR(80) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'security',
                is_active TINYINT(1) NOT NULL DEFAULT 1,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
        return True
    except Error:
        conn.rollback()
        app.logger.exception("Unable to create users table")
        return False
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


def admin_exists():
    if not ensure_users_table():
        return False
    conn = get_db_connection()
    if conn is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        return cursor.fetchone()[0] > 0
    except Error:
        app.logger.exception("Unable to check administrator account")
        return False
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access the security dashboard.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            if session.get("role") != role:
                abort(403)

            # Re-check account status so a deactivated guard loses access
            # even if their browser still has an existing session.
            conn = get_db_connection()
            if conn is None:
                flash("Unable to verify your staff account. Please try again.", "error")
                return redirect(url_for("login"))
            cursor = None
            try:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT role, is_active FROM users WHERE id = %s",
                    (session.get("user_id"),)
                )
                account = cursor.fetchone()
                if not account or not account["is_active"] or account["role"] != role:
                    session.clear()
                    flash("Your account is inactive or no longer authorised. Contact the administrator.", "error")
                    return redirect(url_for("login"))
            except Error:
                app.logger.exception("Unable to verify staff account")
                flash("Unable to verify your staff account.", "error")
                return redirect(url_for("login"))
            finally:
                if cursor is not None:
                    cursor.close()
                conn.close()
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/setup-admin", methods=["GET", "POST"])
def setup_admin():
    """Allow creation of the single initial administrator only once."""
    if admin_exists():
        flash("The administrator account has already been created. Please log in.", "info")
        return redirect(url_for("login"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not full_name or not username or len(username) < 4:
            flash("Enter your name and a username with at least 4 characters.", "error")
        elif len(password) < 10:
            flash("Use an administrator password with at least 10 characters.", "error")
        elif password != confirm_password:
            flash("Passwords do not match.", "error")
        else:
            conn = get_db_connection()
            if conn is None:
                flash("Unable to connect to the database.", "error")
                return render_template("setup_admin.html")
            cursor = None
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                if cursor.fetchone()[0] > 0:
                    flash("An administrator already exists. Please log in.", "error")
                    return redirect(url_for("login"))
                cursor.execute(
                    "INSERT INTO users (full_name, username, password_hash, role, is_active) VALUES (%s, %s, %s, 'admin', 1)",
                    (full_name, username, generate_password_hash(password))
                )
                conn.commit()
                flash("Administrator account created. Please log in.", "success")
                return redirect(url_for("login"))
            except Error:
                conn.rollback()
                app.logger.exception("Unable to create administrator")
                flash("Unable to create administrator. The username may already exist.", "error")
            finally:
                if cursor is not None:
                    cursor.close()
                conn.close()
    return render_template("setup_admin.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    ensure_users_table()
    if session.get("user_id"):
        return redirect(url_for("admin_dashboard" if session.get("role") == "admin" else "dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db_connection()
        if conn is None:
            flash("Unable to connect to the database.", "error")
            return render_template("login.html")
        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s LIMIT 1", (username,))
            user = cursor.fetchone()
            if not user or not user["is_active"] or not check_password_hash(user["password_hash"], password):
                flash("Invalid username or password, or account is inactive.", "error")
            else:
                session.clear()
                session["user_id"] = user["id"]
                session["full_name"] = user["full_name"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                flash(f"Welcome, {user['full_name']}.", "success")
                return redirect(url_for("admin_dashboard" if user["role"] == "admin" else "dashboard"))
        except Error:
            app.logger.exception("Login lookup failed")
            flash("Unable to process login.", "error")
        finally:
            if cursor is not None:
                cursor.close()
            conn.close()
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    conn = get_db_connection()
    if conn is None:
        flash("Unable to connect to the database.", "error")
        return render_template("admin_dashboard.html", guards=[]), 500
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, full_name, username, is_active, created_at FROM users WHERE role = 'security' ORDER BY created_at DESC")
        guards = cursor.fetchall()
        return render_template("admin_dashboard.html", guards=guards)
    except Error:
        app.logger.exception("Unable to load security guard accounts")
        flash("Unable to load security guard accounts.", "error")
        return render_template("admin_dashboard.html", guards=[]), 500
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


@app.route("/admin/guards/create", methods=["POST"])
@role_required("admin")
def create_guard():
    full_name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    if not full_name or len(username) < 4 or len(password) < 8:
        flash("Enter a name, username (at least 4 characters), and password (at least 8 characters).", "error")
        return redirect(url_for("admin_dashboard"))
    conn = get_db_connection()
    if conn is None:
        flash("Unable to connect to the database.", "error")
        return redirect(url_for("admin_dashboard"))
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (full_name, username, password_hash, role, is_active) VALUES (%s, %s, %s, 'security', 1)",
            (full_name, username, generate_password_hash(password))
        )
        conn.commit()
        flash(f"Security guard account created for {full_name}.", "success")
    except Error:
        conn.rollback()
        app.logger.exception("Unable to create security guard account")
        flash("Unable to create account. Check whether the username is already used.", "error")
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/guards/<int:guard_id>/toggle", methods=["POST"])
@role_required("admin")
def toggle_guard(guard_id):
    conn = get_db_connection()
    if conn is None:
        flash("Unable to connect to the database.", "error")
        return redirect(url_for("admin_dashboard"))
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_active = IF(is_active = 1, 0, 1) WHERE id = %s AND role = 'security'", (guard_id,))
        if cursor.rowcount:
            conn.commit()
            flash("Security guard account status updated.", "success")
        else:
            conn.rollback()
            flash("Security guard account not found.", "error")
    except Error:
        conn.rollback()
        app.logger.exception("Unable to update security guard status")
        flash("Unable to update account status.", "error")
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()
    return redirect(url_for("admin_dashboard"))



def send_checkin_email(visitor_data):
    """Send complete visitor registration confirmation email."""

    visitor_email = visitor_data.get("email")

    if not visitor_email:
        return False

    smtp_host = os.getenv("SMTP_HOST")
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender_email = os.getenv("MAIL_FROM") or smtp_username

    if not all((smtp_host, smtp_username, smtp_password, sender_email)):
        app.logger.error("SMTP settings are incomplete; confirmation email not sent.")
        return False

    try:
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() in ("1", "true", "yes")

        message = EmailMessage()
        message["Subject"] = (
            f"Visitor Registration Successful - ID {visitor_data['visitor_id']}"
        )
        message["From"] = sender_email
        message["To"] = visitor_email

        id_reference = visitor_data.get("id_reference") or "Not provided"

        # Mask ID reference for privacy.
        if id_reference != "Not provided" and len(id_reference) > 4:
            id_reference = "*" * (len(id_reference) - 4) + id_reference[-4:]

        declaration_status = (
            "Accepted" if visitor_data.get("declaration") else "Not accepted"
        )

        security_acknowledgement = (
            "Accepted"
            if visitor_data.get("security_acknowledgement")
            else "Not accepted"
        )

        message.set_content(f"""
Dear {visitor_data['full_name']},

Your visitor registration at Government College of Engineering,
Chhatrapati Sambhajinagar has been SUCCESSFULLY completed.

Please find your complete registration details below.

==================================================
             VISITOR REGISTRATION RECEIPT
==================================================

VISITOR INFORMATION

Visitor ID             : {visitor_data['visitor_id']}
Full Name              : {visitor_data['full_name']}
Mobile Number          : {visitor_data['mobile']}
Email Address          : {visitor_email}
Age                    : {visitor_data.get('age') if visitor_data.get('age') is not None else 'Not provided'}
Gender                 : {visitor_data.get('gender') or 'Not provided'}

VISIT INFORMATION

Visitor Category       : {visitor_data['visitor_category']}
Full Address           : {visitor_data.get('address') or 'Not provided'}
City                   : {visitor_data.get('city') or 'Not provided'}
Purpose of Visit       : {visitor_data['purpose']}
Number of Visitors     : {visitor_data['number_of_visitors']}

IDENTITY INFORMATION

ID Proof Type          : {visitor_data['id_type']}
ID Reference           : {id_reference}

REGISTRATION DETAILS

Visit Date             : {visitor_data['visit_date']}
Check-in Time          : {visitor_data['check_in_time']}
Check-out Time         : Not yet recorded
Current Status         : Checked In

DECLARATION

Declaration            : {declaration_status}
Security Acknowledgement: {security_acknowledgement}

==================================================

IMPORTANT INSTRUCTIONS

1. Please keep your Visitor ID for future reference.
2. Your registration has been successfully recorded.
3. Your check-out time will be recorded by authorised security
   staff when you leave the college premises.
4. Please follow all college security rules during your visit.

Thank you for visiting our college.

Regards,
Security Administration

Government College of Engineering,
Chhatrapati Sambhajinagar

==================================================

This is an automatically generated registration confirmation email.
Please do not reply to this email.
""")

        if use_ssl:
            with smtplib.SMTP_SSL(
                smtp_host,
                smtp_port,
                timeout=20,
                context=ssl.create_default_context()
            ) as server:
                server.login(smtp_username, smtp_password)
                server.send_message(message)

        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                server.login(smtp_username, smtp_password)
                server.send_message(message)

        return True

    except Exception:
        app.logger.exception(
            "Unable to send visitor confirmation email to %s",
            visitor_email
        )
        return False


def get_visitor_by_id(cursor, visitor_id):
    cursor.execute(
        "SELECT * FROM visitors WHERE id = %s",
        (visitor_id,)
    )
    return cursor.fetchone()


@app.route("/register", methods=["GET", "POST"], endpoint="register_visitor")
@app.route("/", methods=["GET", "POST"])
def visitor_registration():

    if request.method == "POST":
        # Generate date and time on the server.
        now = datetime.datetime.now()

        full_name = request.form.get("full_name", "").strip()
        mobile = request.form.get("mobile", "").strip()
        email = request.form.get("email", "").strip()
        age_raw = request.form.get("age", "").strip()
        gender = request.form.get("gender", "").strip()
        visitor_category = request.form.get("visitor_category", "").strip()
        address = request.form.get("address", "").strip()
        city = request.form.get("city", "").strip()
        purpose = request.form.get("purpose", "").strip()
        number_of_visitors_raw = request.form.get(
            "number_of_visitors", "1"
        ).strip()
        id_type = request.form.get("id_type", "").strip()
        id_reference = request.form.get("id_reference", "").strip()

        declaration = request.form.get("declaration") == "accepted"
        security_acknowledgement = (
            request.form.get("security_acknowledgement") == "accepted"
        )

        # Validate required fields.
        errors = []

        if not full_name:
            errors.append("Full name is required.")

        if not mobile.isdigit() or len(mobile) != 10:
            errors.append("Enter a valid 10-digit mobile number.")

        if not visitor_category:
            errors.append("Select a visitor category.")

        if not purpose:
            errors.append("Select the purpose of visit.")

        if not id_type:
            errors.append("Select an ID proof type.")

        if not declaration:
            errors.append("Please accept the declaration.")

        # Validate age.
        try:
            age = int(age_raw) if age_raw else None

            if age is not None and not 0 <= age <= 120:
                raise ValueError

        except ValueError:
            errors.append("Enter a valid age.")
            age = None

        # Validate number of visitors.
        try:
            number_of_visitors = int(number_of_visitors_raw)

            if not 1 <= number_of_visitors <= 100:
                raise ValueError

        except ValueError:
            errors.append(
                "Number of visitors must be between 1 and 100."
            )
            number_of_visitors = 1

        if errors:
            for error in errors:
                flash(error, "error")

            return render_template(
                "visitor_form.html",
                form=request.form
            ), 400

        # Save visitor information to MySQL.
        conn = get_db_connection()

        if conn is None:
            flash("Unable to connect to the database.", "error")
            return render_template(
                "visitor_form.html",
                form=request.form
            ), 500

        cursor = None

        try:
            cursor = conn.cursor()

            sql = """
                INSERT INTO visitors (
                    full_name,
                    mobile,
                    email,
                    age,
                    gender,
                    visitor_category,
                    address,
                    city,
                    purpose,
                    number_of_visitors,
                    id_type,
                    id_reference,
                    declaration,
                    security_acknowledgement,
                    visit_date,
                    check_in_time,
                    status
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s
                )
            """

            values = (
                full_name,
                mobile,
                email or None,
                age,
                gender or None,
                visitor_category,
                address or None,
                city or None,
                purpose,
                number_of_visitors,
                id_type,
                id_reference or None,
                declaration,
                security_acknowledgement,
                now.date(),
                now,
                "Checked In"
            )

            cursor.execute(sql, values)
            conn.commit()

            # MySQL generates the visitor ID.
            visitor_id = cursor.lastrowid

            # Send complete registration confirmation email.
            email_sent = send_checkin_email({
                "visitor_id": visitor_id,
                "full_name": full_name,
                "mobile": mobile,
                "email": email,
                "age": age,
                "gender": gender,
                "visitor_category": visitor_category,
                "address": address,
                "city": city,
                "purpose": purpose,
                "number_of_visitors": number_of_visitors,
                "id_type": id_type,
                "id_reference": id_reference,
                "declaration": declaration,
                "security_acknowledgement": security_acknowledgement,
                "visit_date": now.date().isoformat(),
                "check_in_time": now.strftime("%Y-%m-%d %H:%M:%S")
            })

            if email:
                if email_sent:
                    flash(
                        "Registration successful! Confirmation email sent to the visitor.",
                        "success"
                    )
                else:
                    flash(
                        "Visitor registered successfully, but confirmation email could not be sent. Check SMTP settings.",
                        "error"
                    )

            else:
                flash(
                    "Registration successful! No email was provided by the visitor.",
                    "success"
                )

            flash(
                f"Visitor ID: {visitor_id}",
                "success"
            )

            return redirect(url_for("visitor_registration"))

        except Error as e:
            conn.rollback()
            app.logger.exception("Error saving visitor to MySQL")

            flash(
                "Unable to save visitor details. Please try again.",
                "error"
            )

            return render_template(
                "visitor_form.html",
                form=request.form
            ), 500

        finally:
            if cursor is not None:
                cursor.close()

            conn.close()

    return render_template("visitor_form.html", form={})


@app.route("/security/visitors")
@login_required
@role_required("security")
def security_visitors():
    # Load visitor records from MySQL.
    conn = get_db_connection()

    if conn is None:
        flash("Unable to connect to the database.", "error")
        return render_template(
            "security_visitors.html",
            visitors=[]
        ), 500

    cursor = None

    try:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id AS visitor_id,
                full_name,
                mobile,
                email,
                age,
                gender,
                visitor_category,
                address,
                city,
                purpose,
                number_of_visitors,
                id_type,
                id_reference,
                visit_date,
                check_in_time,
                check_out_time,
                status,
                security_acknowledgement
            FROM visitors
            ORDER BY id DESC
        """)

        visitors = cursor.fetchall()

        return render_template(
            "security_visitors.html",
            visitors=visitors
        )

    except Error:
        app.logger.exception("Error retrieving visitors from MySQL")
        flash("Unable to load visitor records.", "error")

        return render_template(
            "security_visitors.html",
            visitors=[]
        ), 500

    finally:
        if cursor is not None:
            cursor.close()

        conn.close()


@app.route("/security/checkout/<int:visitor_id>", methods=["POST"])
@login_required
@role_required("security")
def security_checkout(visitor_id):
    # Update the visitor's checkout details in MySQL.
    conn = get_db_connection()

    if conn is None:
        flash("Unable to connect to the database.", "error")
        return redirect(url_for("security_visitors"))

    cursor = None

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE visitors
            SET check_out_time = %s,
                status = %s
            WHERE id = %s
              AND check_out_time IS NULL
            """,
            (
                datetime.datetime.now(),
                "Checked Out",
                visitor_id
            )
        )

        if cursor.rowcount == 1:
            conn.commit()
            flash(
                f"Visitor {visitor_id} checked out successfully.",
                "success"
            )
        else:
            conn.rollback()
            flash(
                "Visitor not found or already checked out.",
                "error"
            )

    except Error:
        conn.rollback()
        app.logger.exception("Error checking out visitor")
        flash("Unable to process visitor checkout.", "error")

    finally:
        if cursor is not None:
            cursor.close()

        conn.close()

    return redirect(url_for("security_visitors"))


# ---------------------------------------------------------------------
# NEW DASHBOARD ROUTES
# These use the existing MySQL visitors table and its existing columns.
# The original registration and security-visitors routes above are kept.
# ---------------------------------------------------------------------

def dashboard_status(db_status):
    """Convert existing database statuses to labels used by the dashboard."""
    if db_status == "Checked In":
        return "On Campus"
    if db_status == "Checked Out":
        return "Checked Out"
    if db_status == "Expected":
        return "Expected"
    return db_status or "Expected"


def get_dashboard_visitors(cursor, visitor_id=None):
    """Read existing visitor columns and map them to dashboard template names."""
    sql = """
        SELECT
            id,
            id AS visitor_id,
            CONCAT('V-', id) AS badge,
            full_name AS name,
            mobile AS phone,
            email,
            visitor_category AS organization,
            purpose,
            '' AS host,
            '' AS department,
            id_type AS id_proof,
            '' AS vehicle,
            address,
            city,
            age,
            gender,
            number_of_visitors,
            id_reference,
            visit_date,
            check_in_time AS checkin_time,
            check_out_time AS checkout_time,
            status,
            security_acknowledgement,
            declaration
        FROM visitors
    """
    params = ()
    if visitor_id is not None:
        sql += " WHERE id = %s"
        params = (visitor_id,)
    else:
        sql += " ORDER BY id DESC"

    cursor.execute(sql, params)
    rows = cursor.fetchall()

    # Normalize status for the dashboard without changing the database values.
    for row in rows:
        row["status"] = dashboard_status(row.get("status"))
        row["created_at"] = row.get("visit_date")
        row["host"] = row.get("host") or "—"
        row["department"] = row.get("department") or "—"
        row["vehicle"] = row.get("vehicle") or "—"
        row["organization"] = row.get("organization") or "Individual"
    return rows


@app.route("/security/dashboard")
@login_required
@role_required("security")
def dashboard():
    """New dashboard page; keeps / available for the visitor registration QR code."""
    conn = get_db_connection()
    if conn is None:
        flash("Unable to connect to the database.", "error")
        return render_template(
            "security_log.html",
            visitors=[],
            recent=[],
            counts={"on_campus": 0, "expected": 0, "checked_out": 0, "total": 0},
            q="",
            status="All"
        ), 500

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        all_visitors = get_dashboard_visitors(cursor)

        q = request.args.get("q", "").strip().lower()
        selected_status = request.args.get("status", "All")
        allowed_statuses = {"All", "On Campus", "Expected", "Checked Out"}
        if selected_status not in allowed_statuses:
            selected_status = "All"

        counts = {
            "on_campus": sum(v["status"] == "On Campus" for v in all_visitors),
            "expected": sum(v["status"] == "Expected" for v in all_visitors),
            "checked_out": sum(v["status"] == "Checked Out" for v in all_visitors),
            "total": len(all_visitors)
        }

        visitors = all_visitors
        if q:
            visitors = [
                v for v in visitors
                if q in " ".join(str(v.get(key) or "") for key in
                                 ("name", "organization", "badge", "phone", "vehicle")).lower()
            ]
        if selected_status != "All":
            visitors = [v for v in visitors if v["status"] == selected_status]

        return render_template(
            "security_log.html",
            visitors=visitors,
            recent=all_visitors[:6],
            counts=counts,
            q=q,
            status=selected_status
        )

    except Error:
        app.logger.exception("Error loading visitor dashboard")
        flash("Unable to load visitor dashboard.", "error")
        return render_template(
            "security_log.html",
            visitors=[],
            recent=[],
            counts={"on_campus": 0, "expected": 0, "checked_out": 0, "total": 0},
            q="",
            status="All"
        ), 500
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


@app.route("/security/visitor/<int:visitor_id>")
@login_required
@role_required("security")
def visitor_detail(visitor_id):
    conn = get_db_connection()
    if conn is None:
        flash("Unable to connect to the database.", "error")
        return redirect(url_for("dashboard"))

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        rows = get_dashboard_visitors(cursor, visitor_id)
        if not rows:
            flash("Visitor record not found.", "error")
            return redirect(url_for("dashboard"))
        return render_template("visitor_detail.html", visitor=rows[0])
    except Error:
        app.logger.exception("Error loading visitor details")
        flash("Unable to load visitor details.", "error")
        return redirect(url_for("dashboard"))
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


@app.route("/security/visitor/<int:visitor_id>/checkin", methods=["POST"])
@login_required
@role_required("security")
def checkin_visitor(visitor_id):
    conn = get_db_connection()
    if conn is None:
        flash("Unable to connect to the database.", "error")
        return redirect(url_for("dashboard"))

    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE visitors
            SET check_in_time = %s, check_out_time = NULL, status = %s
            WHERE id = %s AND status = %s
            """,
            (datetime.datetime.now(), "Checked In", visitor_id, "Expected")
        )
        if cursor.rowcount == 1:
            conn.commit()
            flash("Visitor checked in successfully.", "success")
        else:
            conn.rollback()
            flash("Only expected visitors can be checked in.", "error")
    except Error:
        conn.rollback()
        app.logger.exception("Error checking in visitor")
        flash("Unable to process visitor check-in.", "error")
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/security/visitor/<int:visitor_id>/checkout", methods=["POST"])
@login_required
@role_required("security")
def checkout_visitor(visitor_id):
    # Keep the original checkout route working and expose the route name
    # expected by the new dashboard template.
    conn = get_db_connection()
    if conn is None:
        flash("Unable to connect to the database.", "error")
        return redirect(url_for("dashboard"))

    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE visitors
            SET check_out_time = %s, status = %s
            WHERE id = %s AND status = %s AND check_out_time IS NULL
            """,
            (datetime.datetime.now(), "Checked Out", visitor_id, "Checked In")
        )
        if cursor.rowcount == 1:
            conn.commit()
            flash("Visitor checked out successfully.", "success")
        else:
            conn.rollback()
            flash("Visitor not found, not checked in, or already checked out.", "error")
    except Error:
        conn.rollback()
        app.logger.exception("Error checking out visitor from dashboard")
        flash("Unable to process visitor checkout.", "error")
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/security/visitor/<int:visitor_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("security")
def edit_visitor(visitor_id):
    # Reuse the existing visitor_form.html fields for editing an existing record.
    conn = get_db_connection()
    if conn is None:
        flash("Unable to connect to the database.", "error")
        return redirect(url_for("dashboard"))

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM visitors WHERE id = %s", (visitor_id,))
        visitor = cursor.fetchone()
        if visitor is None:
            flash("Visitor record not found.", "error")
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            mobile = request.form.get("mobile", "").strip()
            purpose = request.form.get("purpose", "").strip()
            if not full_name or not mobile.isdigit() or len(mobile) != 10 or not purpose:
                flash("Enter a name, valid 10-digit mobile number, and purpose.", "error")
                form = request.form
                return render_template("visitor_form.html", form=form, editing=True, visitor=visitor), 400

            age_raw = request.form.get("age", "").strip()
            try:
                age = int(age_raw) if age_raw else None
                if age is not None and not 0 <= age <= 120:
                    raise ValueError
            except ValueError:
                flash("Enter a valid age.", "error")
                return render_template("visitor_form.html", form=request.form, editing=True, visitor=visitor), 400

            try:
                number_of_visitors = int(request.form.get("number_of_visitors", "1"))
                if not 1 <= number_of_visitors <= 100:
                    raise ValueError
            except ValueError:
                flash("Number of visitors must be between 1 and 100.", "error")
                return render_template("visitor_form.html", form=request.form, editing=True, visitor=visitor), 400

            cursor.execute(
                """
                UPDATE visitors SET
                    full_name=%s, mobile=%s, email=%s, age=%s, gender=%s,
                    visitor_category=%s, address=%s, city=%s, purpose=%s,
                    number_of_visitors=%s, id_type=%s, id_reference=%s,
                    declaration=%s, security_acknowledgement=%s
                WHERE id=%s
                """,
                (
                    full_name, mobile, request.form.get("email", "").strip() or None,
                    age, request.form.get("gender", "").strip() or None,
                    request.form.get("visitor_category", "").strip(),
                    request.form.get("address", "").strip() or None,
                    request.form.get("city", "").strip() or None,
                    purpose, number_of_visitors,
                    request.form.get("id_type", "").strip(),
                    request.form.get("id_reference", "").strip() or None,
                    request.form.get("declaration") == "accepted",
                    request.form.get("security_acknowledgement") == "accepted",
                    visitor_id
                )
            )
            conn.commit()
            flash("Visitor record updated.", "success")
            return redirect(url_for("visitor_detail", visitor_id=visitor_id))

        # Map database field names to the names used by visitor_form.html.
        form = dict(visitor)
        form["full_name"] = visitor.get("full_name", "")
        return render_template("visitor_form.html", form=form, editing=True, visitor=visitor)

    except Error:
        conn.rollback()
        app.logger.exception("Error editing visitor")
        flash("Unable to update visitor record.", "error")
        return redirect(url_for("dashboard"))
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


if __name__ == "__main__":
    app.run(debug=True)
