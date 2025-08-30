from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, ScanResult, ContactMessage
import re
import dns.resolver
from analyze import extract_all_features, classify_website

app = Flask(__name__)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'
db.init_app(app)

# Utility Functions
def is_email(input_value):
    return re.match(r"[^@]+@[^@]+\.[^@]+", input_value)

def check_mx_record(domain):
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        return False

# Home Page
@app.route('/')
def home():
    return render_template("index.html")

# Universal Checker
@app.route('/universal-checker', methods=["GET", "POST"])
def universal_checker():
    result = None
    input_value = ""

    if request.method == "POST":
        input_value = request.form["input_value"]

        if is_email(input_value):
            domain = input_value.split("@")[1]
            reasons = []
            if not check_mx_record(domain):
                reasons.append("❌ No MX record found for domain.")
            else:
                reasons.append("✅ MX record exists.")
            verdict = "Real" if not reasons or "✅" in reasons[0] else "Fake"
            result = {
                "type": "email",
                "verdict": verdict,
                "reasons": reasons
            }
        else:
            try:
                features = extract_all_features(input_value)
                verdict, reasons = classify_website(features)
                result = {
                    "type": "website",
                    "verdict": verdict,
                    "features": features,
                    "reasons": reasons
                }
            except Exception as e:
                result = {"type": "error", "error": str(e)}

        # Save to database
        if result["type"] in ["email", "website"]:
            db.session.add(ScanResult(
                input_value=input_value,
                input_type=result["type"],
                verdict=result["verdict"],
                reasons=", ".join(result["reasons"])
            ))
            db.session.commit()

    return render_template("universal_checker.html", result=result, input_value=input_value)

# Contact Page
@app.route('/contact', methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        message = request.form["message"]
        new_message = ContactMessage(name=name, email=email, message=message)
        db.session.add(new_message)
        db.session.commit()
        return render_template("thank_you.html")

    return render_template("contact.html")

# About Page
@app.route('/about')
def about():
    return render_template("about.html")

# Register Page
@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password == confirm_password:
            hashed_password = generate_password_hash(password)
            new_user = User(email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match!', 'danger')

    return render_template('register.html')

# Login Page
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user'] = email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

# Dashboard Page
@app.route('/dashboard')
def dashboard():
    if not session.get('user'):
        return redirect(url_for('login'))

    user_email = session['user']
    # Get both website and email scan results, latest first
    all_results = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    return render_template('dashboard.html', user=user_email, results=all_results)


@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

