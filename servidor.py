from flask import Flask, request, jsonify, make_response
from flask_cors import CORS # <--
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from datetime import datetime, timedelta
import os

app = Flask(__name__) 
CORS(app, supports_credentials=True, resources={ # <--
    r"/*": {
        "origins": ["http://localhost:5173", "https://pj-fronted.onrender.com", "https://pj-backend-bs1t.onrender.com"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Set-Cookie", "Authorization"],
        "supports_credentials": True
    }
})

# ---------------------------
# Configuración base de datos (en Render)
# ---------------------------
DATABASE_URL = os.environ.get("DATABASE_URL")  # <- Render te da esta URL

def get_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL no está definida en Render")
    return psycopg2.connect(DATABASE_URL)

# ---------------------------
# Inicialización
# ---------------------------
def init_db():
    conn = get_connection()
    cur = conn.cursor()

    # Tabla usuarios
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_superuser BOOLEAN DEFAULT FALSE
        )
    """)

    # Tabla juegos (usar 'anio' para evitar problemas de encoding)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS juegos (
            id SERIAL PRIMARY KEY,
            titulo TEXT NOT NULL,
            anio INT,
            genero TEXT,
            url TEXT,
            imagen TEXT
        )
    """)

    # Insertar admin por defecto si no existe
    cur.execute("SELECT id FROM usuarios WHERE username = %s", ('admin',))
    if not cur.fetchone():
        pwd_hash = generate_password_hash('admin')
        cur.execute(
            "INSERT INTO usuarios (username, password_hash, is_superuser) VALUES (%s, %s, %s)",
            ('admin', pwd_hash, True)
        )

    conn.commit()
    cur.close()
    conn.close()

init_db()

# ---------------------------
# Helpers de auth (JWT)
# ---------------------------
def generate_token(username, is_superuser, expires_minutes=120):
    payload = {
        "sub": username,
        "is_superuser": bool(is_superuser),
        "exp": datetime.utcnow() + timedelta(minutes=expires_minutes)
    }
    # Diagnóstico si el jwt importado no es PyJWT
    if not hasattr(jwt, "encode"):
        raise RuntimeError(
            "El módulo 'jwt' importado no tiene 'encode'. "
            "Asegúrate de instalar PyJWT (pip install PyJWT) y que no haya un archivo local jwt.py."
        )
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    # Normalizar a str (PyJWT v1 puede devolver bytes)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def requires_superuser(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        print("Cookies recibidas:", request.cookies)
        token = request.cookies.get("token")  # <-- leemos la cookie
        if not token:
            # Si no hay cookie, también podemos permitir Authorization header
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1].strip()

        if not token:
            return jsonify({"mensaje": "Token requerido"}), 401

        payload = verify_token(token)
        if not payload:
            return jsonify({"mensaje": "Token inválido o expirado"}), 401

        if not payload.get("is_superuser"):
            return jsonify({"mensaje": "Acceso denegado: superusuario requerido"}), 403

        request.user = payload.get("sub")
        return f(*args, **kwargs)
    return decorated


# ---------------------------
# Rutas de autenticación
# ---------------------------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    print("Datos recibidos en /login:", data)
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"mensaje": "username y password requeridos"}), 400

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash, is_superuser FROM usuarios WHERE username = %s", (username,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row and check_password_hash(row[0], password):
        token = generate_token(username, row[1])
        # Creamos la respuesta
        resp = make_response(jsonify({
            "mensaje": "Login correcto",
            "is_superuser": bool(row[1])
        }), 200)

        # Guardamos la cookie segura, HTTPOnly
        resp.set_cookie(
            "token", token,
            httponly=True,      # No accesible desde JS
            samesite='None',  # LO HE CAMBIADO A NONE PARA QUE FUNCIONE EN LOCALHOST <---
            secure=True        # True si usas HTTPS <---
        )
        return resp

    return jsonify({"mensaje": "Credenciales incorrectas"}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"mensaje": "username y password requeridos"}), 400

    conn = get_connection()
    cur = conn.cursor()

    # Verificar si el usuario ya existe
    cur.execute("SELECT id FROM usuarios WHERE username = %s", (username,))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({"mensaje": "El usuario ya existe"}), 409

    # Crear usuario
    pwd_hash = generate_password_hash(password)
    cur.execute(
        "INSERT INTO usuarios (username, password_hash, is_superuser) VALUES (%s, %s, %s) RETURNING id",
        (username, pwd_hash, False)
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"mensaje": "Usuario registrado correctamente"}), 201

@app.route('/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({"mensaje": "Logout correcto"}), 200)
    resp.delete_cookie("token")
    return resp

# ---------------------------
# CRUD juegos
# ---------------------------
@app.route('/juegos', methods=['GET'])
def listar_juegos():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, titulo, anio, genero, url, imagen FROM juegos ORDER BY id")
    juegos = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{ "id": j[0], "titulo": j[1], "anio": j[2], "genero": j[3], "url": j[4], "imagen": j[5]} for j in juegos]), 200

@app.route('/juegos', methods=['POST'])
@requires_superuser
def añadir_juego():
    data = request.get_json(force=True)
    titulo = data.get('titulo')
    anio = data.get('anio')
    genero = data.get('genero')
    url = data.get('url')
    imagen = data.get('imagen')

    if not titulo:
        return jsonify({"mensaje": "titulo es obligatorio"}), 400
    if not url:
        url = f"https://www.google.com/search?q={titulo.replace(' ', '+')}"

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO juegos (titulo, anio, genero, url, imagen) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (titulo, anio, genero, url, imagen))
    new_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"mensaje": "Juego añadido", "id": new_id, "url": url}), 201

@app.route('/juegos/<int:game_id>', methods=['PUT'])
@requires_superuser
def actualizar_juego(game_id):
    data = request.get_json(force=True) or {}
    fields = {}
    if 'titulo' in data:
        fields['titulo'] = data['titulo']
    if 'anio' in data:
        fields['anio'] = data['anio']
    if 'genero' in data:
        fields['genero'] = data['genero']
    if 'url' in data:
        fields['url'] = data['url']
    if 'imagen' in data:
        fields['imagen'] = data['imagen']


    if not fields:
        return jsonify({"mensaje": "Nada que actualizar"}), 400

    set_clause = ", ".join([f"{k} = %s" for k in fields.keys()])
    params = list(fields.values()) + [game_id]

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"UPDATE juegos SET {set_clause} WHERE id = %s RETURNING id", params)
    updated = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    if updated:
        return jsonify({"mensaje": "Juego actualizado", "id": game_id}), 200
    return jsonify({"mensaje": "Juego no encontrado"}), 404

@app.route('/juegos/<int:game_id>', methods=['DELETE'])
@requires_superuser
def eliminar_juego(game_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM juegos WHERE id = %s RETURNING id", (game_id,))
    deleted = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    if deleted:
        return jsonify({"mensaje": "Juego eliminado", "id": deleted[0]}), 200
    return jsonify({"mensaje": "Juego no encontrado"}), 404


from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join(os.getcwd(), "static", "imagenes")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_image', methods=['POST'])
@requires_superuser   # 👈 Añade esta línea
def upload_image():
    """
    Sube una imagen al servidor y devuelve la ruta pública.
    """
    if 'file' not in request.files:
        return jsonify({"mensaje": "No se ha enviado ningún archivo"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"mensaje": "Archivo vacío"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(save_path)
        public_url = f"/static/imagenes/{filename}"
        return jsonify({"mensaje": "Imagen subida correctamente", "url": public_url}), 200

    return jsonify({"mensaje": "Formato de archivo no permitido"}), 400


if __name__ == '__main__':
    app.run(debug=True)




