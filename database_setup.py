import sqlite3

# Conexión a la base de datos
conn = sqlite3.connect('passwords.db')
cursor = conn.cursor()

# Creación de la tabla "passwords"
cursor.execute("CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, description TEXT, site TEXT, username TEXT, password TEXT)")

# Creación de la tabla "users"
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
""")

# Guardar cambios y cerrar la conexión
conn.commit()
conn.close()