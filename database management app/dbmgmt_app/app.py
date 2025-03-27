from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import MetaData, Table, Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.sql import text

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

metadata = MetaData()

# User model for authentication
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize database with admin user
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password) and user.is_admin:
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials or not an admin')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for('login'))
    
    # Reflect current database structure
    metadata.reflect(bind=db.engine)
    tables = metadata.tables.keys()
    return render_template('dashboard.html', tables=tables)

@app.route('/create_table', methods=['POST'])
@login_required
def create_table():
    if not current_user.is_admin:
        return redirect(url_for('login'))
    
    table_name = request.form['table_name']
    try:
        # Create a basic table with an ID column
        new_table = Table(
            table_name, metadata,
            Column('id', Integer, primary_key=True)
        )
        new_table.create(db.engine)
        flash(f'Table {table_name} created successfully')
    except Exception as e:
        flash(f'Error creating table: {str(e)}')
    return redirect(url_for('dashboard'))

@app.route('/table/<table_name>', methods=['GET', 'POST'])
@login_required
def edit_table(table_name):
    if not current_user.is_admin:
        return redirect(url_for('login'))
    
    metadata.reflect(bind=db.engine)
    if table_name not in metadata.tables:
        flash('Table not found')
        return redirect(url_for('dashboard'))
    
    table = metadata.tables[table_name]
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_column':
            try:
                column_name = request.form['column_name']
                column_type = request.form['column_type']
                is_foreign_key = request.form.get('is_foreign_key') == 'on'
                
                # Map form input to SQLAlchemy types
                type_map = {
                    'integer': Integer,
                    'string': String(255)
                }
                col_type = type_map.get(column_type, String(255))
                
                if is_foreign_key:
                    fk_table = request.form['fk_table']
                    fk_column = request.form['fk_column']
                    with db.engine.connect() as conn:
                        conn.execute(text(f"""
                            ALTER TABLE {table_name}
                            ADD COLUMN {column_name} {column_type}
                            REFERENCES {fk_table}({fk_column})
                        """))
                else:
                    with db.engine.connect() as conn:
                        conn.execute(text(f"""
                            ALTER TABLE {table_name}
                            ADD COLUMN {column_name} {column_type}
                        """))
                metadata.clear()
                flash(f'Column {column_name} added successfully')
            except Exception as e:
                flash(f'Error adding column: {str(e)}')
        
        elif action == 'delete_column':
            try:
                column_name = request.form['column_name']
                with db.engine.connect() as conn:
                    conn.execute(text(f"""
                        ALTER TABLE {table_name}
                        DROP COLUMN {column_name}
                    """))
                metadata.clear()
                flash(f'Column {column_name} deleted successfully')
            except Exception as e:
                flash(f'Error deleting column: {str(e)}')
    
    metadata.reflect(bind=db.engine)
    table = metadata.tables[table_name]
    all_tables = metadata.tables.keys()
    return render_template('table_edit.html', table=table, table_name=table_name, all_tables=all_tables)

if __name__ == '__main__':
    app.run(debug=True)
