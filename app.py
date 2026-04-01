''' 

<script>alert("Hacked")</script>' 



'''
from flask import Flask, request
import sqlite3, os

app = Flask(__name__)

# 1. Створення бази даних (щоразу очищуємо для тестів)
def init_db():
    with sqlite3.connect("users.db") as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
        conn.execute("DELETE FROM users")
        conn.execute("INSERT INTO users VALUES ('admin', 'secret_password')")
        conn.commit()

init_db()

@app.route("/")
def index():
    return '''
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 40px auto; line-height: 1.6; }
        section { border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 8px; }
        input[type="text"] { width: 100%; margin-bottom: 10px; padding: 5px; }
    </style>
    <h1>Стенд для тестування вразливостей</h1>
    
    <section>
        <h3>1. SQL Injection та XSS</h3>
        <form action="/login" method="post">
            Логін: <input type="text" name="username" placeholder="admin' -- ">
            Пароль: <input type="text" name="password" placeholder="будь-що">
            <input type="submit" value="Увійти">
        </form>
    </section>

    <section>
        <h3>2. Path Traversal</h3>
        <form action="/file" method="get">
            Назва файлу: <input type="text" name="name" placeholder="../../etc/passwd або app.py">
            <input type="submit" value="Читати файл">
        </form>
    </section>

    <section>
        <h3>3. Command Injection</h3>
        <form action="/run" method="post">
            Команда: <input type="text" name="cmd" placeholder="ls; id або dir & whoami">
            <input type="submit" value="Виконати в системі">
        </form>
    </section>
    '''

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    # Вразливість SQLi: пряма конкатенація
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"[*] Виконується SQL запит: {query}") 

    try:
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            result = cursor.fetchone()
            
            if result:
                # Вразливість XSS: виводимо username прямо в HTML без очищення
                return f"<h2>Вітаємо, {username}!</h2><p>Вхід виконано успішно.</p><a href='/'>Назад</a>"
            else:
                return "<h2>Помилка: Невірні дані.</h2><a href='/'>Назад</a>"
    except Exception as e:
        return f"<h2>Помилка SQL:</h2><pre>{e}</pre><a href='/'>Назад</a>"

@app.route("/file", methods=["GET"])
def file():
    filename = request.args.get("name", "")
    try:
        # Вразливість Path Traversal: відкриваємо шлях як є
        print(f"[*] Спроба відкрити файл: {filename}")
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
            return f"<h3>Вміст файлу {filename}:</h3><pre>{content}</pre><a href='/'>Назад</a>"
    except Exception as e:
        return f"<h2>Помилка файлової системи:</h2><pre>{e}</pre><a href='/'>Назад</a>"

@app.route("/run", methods=["POST"])
def run():
    cmd = request.form.get("cmd", "")
    print(f"[*] Виконується системна команда: {cmd}")
    try:
        # Вразливість Command Injection: виконання через оболонку (shell)
        result = os.popen(cmd).read()
        return f"<h3>Результат команди:</h3><pre>{result}</pre><a href='/'>Назад</a>"
    except Exception as e:
        return f"<h2>Помилка виконання:</h2><pre>{e}</pre><a href='/'>Назад</a>"

if __name__ == "__main__":
    # Запускаємо на порту 5003
    app.run(host="127.0.0.1", port=5003, debug=True)