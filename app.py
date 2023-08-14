import os
import hashlib
import sqlite3
import bcrypt
from flask import Flask, render_template, request, redirect, session, make_response
from flask_sqlalchemy import SQLAlchemy
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Obtenga la clave secreta de las variables de entorno
db_path = os.path.join(os.path.dirname(__file__), 'sistema.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    return redirect('/login')

# Ruta de registro de usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        new_user = User(username=username, password=password) # type: ignore
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect('/login')
        except SQLAlchemyError:
            db.session.rollback()
            return "Error al registrar el usuario"
    return render_template('register.html')

# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect('/dashboard')
        else:
            return "Usuario o contraseña inválidos"
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Mostrar el nombre de usuario con sesión abierta
@app.route('/passwords')
def passwords():
    username = session.get('username')
    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords")
    passwords = cursor.fetchall()
    cursor.execute("SELECT * FROM passwords WHERE site LIKE ? OR username LIKE ?",
                   ('%%', '%%'))
    search_results = cursor.fetchall()
    conn.close()
    return render_template('passwords.html', username=username, passwords=passwords, search_results=search_results)

# Ruta de cierre de sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

# Verificar la autenticación en todas las rutas
@app.before_request
def require_login(): # type: ignore
    allowed_routes = ['login', 'register', '/', '/home']
    if request.endpoint not in allowed_routes and 'username' not in session:
        return redirect('/login')

# Ruta para agregar una nueva contraseña
@app.route('/add_password', methods=['POST'])
def add_password():
    description = request.form['description']
    site = request.form['site']
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (description, site, username, password) VALUES (?, ?, ?, ?)",
                   (description, site, username, password))
    conn.commit()
    conn.close()

    return redirect('/')

# Ruta de búsqueda
@app.route('/search')
def search():
    query = request.args.get('query')

    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE site LIKE ? OR username LIKE ?",
                   ('%'+query+'%', '%'+query+'%')) # type: ignore
    search_results = cursor.fetchall()
    conn.close()

    return render_template('passwords.html', passwords=passwords, search_results=search_results)

# Ruta del calendario
@app.route('/calendar')
def calendar():
    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()
    cursor.execute('SELECT evento, fecha, hora FROM calendario')
    events = cursor.fetchall()
    conn.close()

    return render_template('calendar.html', events=events)


# Ruta del formulario de inventario
@app.route('/inventory')
def inventory():
    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM inventario')
    items = cursor.fetchall()
    conn.close()

    return render_template('inventory.html', inventory_items=items)


# Ruta de formulario de solicitudes
@app.route('/requests')
def user_requests():
    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()

    # Consulta a la tabla "users" para obtener los usuarios
    cursor.execute("SELECT username FROM users")
    users = [row[0] for row in cursor.fetchall()]

    # Consulta a la tabla "solicitudes_estados" para obtener los estados
    cursor.execute("SELECT descripcion FROM solicitudes_estados")
    states = [row[0] for row in cursor.fetchall()]

    # Consulta a la tabla "solicitudes_servicio" para obtener los servicios
    cursor.execute("SELECT descripcion FROM solicitudes_servicio")
    services = [row[0] for row in cursor.fetchall()]

    # Consulta a la tabla "prioridad" para obtener las prioridades
    cursor.execute("SELECT descripcion FROM prioridad")
    priorities = [row[0] for row in cursor.fetchall()]

    # Cierre de la conexión a la base de datos
    conn.close()

    # Renderización de la plantilla requests.html con los datos obtenidos de la base de datos
    return render_template('requests.html', username=session.get('username'), users=users, states=states, services=services, priorities=priorities)

# Ruta para guardar una solicitud de usuario
@app.route('/save_request', methods=['POST'])
def save_request():
    user_id = get_user_id(session.get('username'))
    title = request.form['title']
    description = request.form['description']
    state = request.form['state']
    service = request.form['service']
    priority = request.form['priority']

    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO solicitudes (user_id, title, description, state, service, priority) VALUES (?, ?, ?, ?, ?, ?)',
                   (user_id, title, description, state, service, priority))
    conn.commit()
    conn.close()

    return redirect('/requests')

# Obtener el ID de usuario
def get_user_id(username):
    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user_id = cursor.fetchone()[0]
    conn.close()
    return user_id

# Obtener solicitudes de usuario
def get_user_requests(user_id):
    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM solicitudes WHERE user_id = ?', (user_id,))
    requests = cursor.fetchall()
    conn.close()
    return requests

# Verificar la autenticación en todas las rutas
@app.before_request
def require_login():
    allowed_routes = ['login', 'register', '/', '/home']
    if request.endpoint not in allowed_routes and 'username' not in session:
        return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
