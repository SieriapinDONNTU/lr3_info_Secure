from flask import Flask, request, render_template_string, abort
import sqlite3
import os
import subprocess
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Сховище для файлів (обмежуємо доступ лише цією папкою)
UPLOAD_FOLDER = 'safe_files'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def init_db():
    with sqlite3.connect("users.db") as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
        conn.execute("DELETE FROM users")
        # У реальному житті паролі мають бути хешовані (напр. Werkzeug Security)
        conn.execute("INSERT INTO users VALUES ('admin', 'secret_password')")
        conn.commit()

init_db()

@app.route("/")
def index():
    return '''
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 40px auto; line-height: 1.6; }
        section { border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 8px; }
    </style>
    <h1>Захищений додаток</h1>
    
    <section>
        <h3>1. Захист від SQLi та XSS</h3>
        <form action="/login" method="post">
            Логін: <input type="text" name="username"><br>
            Пароль: <input type="password" name="password"><br>
            <input type="submit" value="Увійти">
        </form>
    </section>

    <section>
        <h3>2. Захист від Path Traversal</h3>
        <form action="/file" method="get">
            Назва файлу: <input type="text" name="name">
            <input type="submit" value="Читати файл">
        </form>
    </section>

    <section>
        <h3>3. Захист від Command Injection</h3>
        <form action="/run" method="post">
            Введіть IP для пінгу: <input type="text" name="ip">
            <input type="submit" value="Перевірити зв'язок">
        </form>
    </section>
    '''

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    # ЗАХИСТ ВІД SQLi: Використовуємо параметризовані запити (?)
    # Дані користувача не вставляються в рядок, а передаються окремо
    query = "SELECT * FROM users WHERE username=? AND password=?"
    
    try:
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute(query, (username, password))
            result = cursor.fetchone()
            
            if result:
                # ЗАХИСТ ВІД XSS: render_template_string автоматично екранує змінні {{ }}
                # Тобто <script> перетвориться на &lt;script&gt; і не виконається
                return render_template_string("<h2>Вітаємо, {{ user }}!</h2><a href='/'>Назад</a>", user=username)
            else:
                return "<h2>Помилка: Невірні дані.</h2><a href='/'>Назад</a>"
    except Exception:
        return "Виникла внутрішня помилка."

@app.route("/file", methods=["GET"])
def file():
    filename = request.args.get("name", "")
    
    # ЗАХИСТ ВІД Path Traversal:
    # 1. secure_filename видаляє "../../" та інші небезпечні символи
    safe_name = secure_filename(filename)
    # 2. Формуємо повний шлях лише всередині дозволеної папки
    file_path = os.path.join(UPLOAD_FOLDER, safe_name)
    
    try:
        if not os.path.exists(file_path):
            return "Файл не знайдено."
            
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            return render_template_string("<h3>Вміст:</h3><pre>{{ data }}</pre><a href='/'>Назад</a>", data=content)
    except Exception:
        return "Помилка доступу."

@app.route("/run", methods=["POST"])
def run():
    ip = request.form.get("ip", "")
    
    # ЗАХИСТ ВІД Command Injection:
    # Замість os.popen(cmd) використовуємо subprocess.run з shell=False
    # Це сприймає ввід користувача як ОДИН аргумент, а не як команду
    try:
        # Ми дозволяємо лише команду 'ping' і передаємо IP як аргумент
        process = subprocess.run(
            ["ping", "-c", "1" if os.name != 'nt' else "-n", "1", ip],
            capture_output=True, 
            text=True, 
            shell=False, # ЦЕ КЛЮЧОВИЙ МОМЕНТ ЗАХИСТУ
            timeout=5
        )
        return f"<h3>Результат:</h3><pre>{process.stdout or process.stderr}</pre><a href='/'>Назад</a>"
    except Exception as e:
        return f"Помилка: {str(e)}"

if __name__ == "__main__":
    app.run(port=5003)
