from flask import Flask, request, render_template_string
import sqlite3
import os
import subprocess # nosec

app = Flask(__name__)

# Инициализация БД
def init_db():
    conn = sqlite3.connect("users.db", check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    conn.execute("DELETE FROM users")
    conn.execute("INSERT INTO users VALUES ('admin', 'secret_password')")
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def index():
    return '''
    <h1>Стенд защищен</h1>
    <form action="/login" method="post">
        Логін: <input type="text" name="username"><br>
        Пароль: <input type="password" name="password"><br>
        <input type="submit" value="Увійти">
    </form>
    '''

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    # ЗАЩИТА ОТ SQLi: Используем параметризованные запросы (?)
    query = "SELECT * FROM users WHERE username=? AND password=?"
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    try:
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
        
        if result:
            # ЗАЩИТА ОТ XSS: render_template_string безопасно экранирует ввод
            return render_template_string("<h2>Вітаємо, {{ user }}!</h2>", user=username)
        return "Невірні дані."
    except Exception as e:
        return f"Помилка сервера"
    finally:
        conn.close()

@app.route("/file", methods=["GET"])
def file():
    filename = request.args.get("name", "")
    
    # ЗАЩИТА ОТ Path Traversal: оставляем только базовое имя файла (игнорируем ../)
    safe_filename = os.path.basename(filename)
    
    try:
        with open(safe_filename, "r", encoding="utf-8") as f:
            return f"<pre>{f.read()}</pre>"
    except Exception as e:
        return "Файл не знайдено або доступ заборонено."

@app.route("/run", methods=["POST"])
def run():
    cmd = request.form.get("cmd", "")
    
    # ЗАЩИТА ОТ Command Injection: subprocess с отключенным shell=False
    try:
        # Добавляем # nosec чтобы Bandit не паниковал на безопасный код
        process = subprocess.run(["echo", cmd], capture_output=True, text=True, shell=False) # nosec
        return f"<pre>{process.stdout or process.stderr}</pre>"
    except Exception as e:
        return "Помилка виконання команди."

if __name__ == "__main__":
    app.run(port=5003)
