import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Secure code: Prevent SQL Injection
@app.route('/get-user', methods=['GET'])
def get_user():
    user_id = request.args.get('user_id')
    if not user_id.isdigit():
        return "Invalid input"
    
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # Use parameterized queries to prevent SQL injection
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchall()
    conn.close()
    return str(result)

if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode
