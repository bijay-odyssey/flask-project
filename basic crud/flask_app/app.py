from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database
with app.app_context():
    db.create_all()
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            password=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        try:
            # Validate email
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError as e:
            flash('Invalid email address')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('register'))
            
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return render_template('user_dashboard.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/update/<int:id>', methods=['POST'])
@login_required
def update_user(id):
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    user = User.query.get_or_404(id)
    new_username = request.form['username']
    new_email = request.form['email']
    
    if new_username != user.username and User.query.filter_by(username=new_username).first():
        flash('Username already exists')
        return redirect(url_for('admin_dashboard'))
        
    try:
        # Validate email
        valid = validate_email(new_email)
        new_email = valid.email
    except EmailNotValidError as e:
        flash('Invalid email address')
        return redirect(url_for('admin_dashboard'))
        
    if new_email != user.email and User.query.filter_by(email=new_email).first():
        flash('Email already exists')
        return redirect(url_for('admin_dashboard'))
        
    user.username = new_username
    user.email = new_email
    if request.form['password']:
        user.password = generate_password_hash(request.form['password'])
    db.session.commit()
    flash('User updated successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:id>')
@login_required
def delete_user(id):
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    user = User.query.get_or_404(id)
    if user.is_admin:
        flash('Cannot delete admin user')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
