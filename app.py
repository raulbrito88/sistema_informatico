import hashlib
from flask import Flask, render_template, request, redirect, session, make_response
import hashlib
import sqlite3

app = Flask(__name__)
app.secret_key = 'Meromero88*'  # Cambia esto a una clave secreta fuerte

@app.route('/')
def home():
    return redirect('/login')

# Ruta de registro de usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('sistema.db')
        cursor = conn.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (username, hashed_password))
        conn.commit()
        conn.close()

        return redirect('/login')

    # Desactivar la caché
    response = make_response(render_template('register.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('sistema.db')
        cursor = conn.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                       (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['username'] = user[1]
            return redirect('/dashboard')
        else:
            error_message = "¡Usuario o contraseña inválidos!"  # Mensaje de error
            return render_template('login.html', error_message=error_message)

    # Desactivar la caché
    response = make_response(render_template('login.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords")
    passwords = cursor.fetchall()
    cursor.execute("SELECT * FROM passwords WHERE site LIKE ? OR username LIKE ?",
                   ('%%', '%%'))
    search_results = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', username=username, passwords=passwords, search_results=search_results)

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
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect('/login')

# Verificar la autenticación en todas las rutas
@app.before_request
def require_login():
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
                   ('%'+query+'%', '%'+query+'%'))
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
