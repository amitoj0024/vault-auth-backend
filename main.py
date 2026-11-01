from flask import Flask, request, jsonify, session
from flask_cors import CORS
import os
from pathlib import Path
from dotenv import load_dotenv

from opperation import get_users, register, auth_user
from api.token import generate_token, session_token

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("TOKEN_SECRET", "vault-auth-secret-key-change-in-production")

CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

@app.route("/api/users", methods=["GET"])
def users():
    try:
        user_list = get_users(None)
        if user_list is not None:
            return jsonify(user_list)
        else:
            return jsonify({"message": "Error getting users"}), 500
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route("/api/users/<int:uid>", methods=["GET"])
def users_id(uid):
    try:
        user = get_users(uid)
        if user is not None:
            return jsonify(user)
        else:
            return jsonify({"message": "Error: User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route("/api/users/<string:id>", methods=["GET"])
def username(id):
    try:
        user = get_users(id)
        if user is not None:
            return jsonify(user)
        else:
            return jsonify({"message": "Error: User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route("/api/register", methods=["POST"])
def create_user():
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Data is null"}), 400
    try:
        result = register(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500
    
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Data is null"}), 400

    login_identifier = data.get("login") or data.get("username")
    password = data.get("password")
    if not login_identifier or not password:
        return jsonify({"message": "User not found"}), 404

    try:
        result = auth_user(login_identifier, password)
        if not result or (isinstance(result, str) and result.startswith("Error")):
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

    try:
        if isinstance(result, dict):
            uid = result.get("uid") or result.get("id") or 0
            user = result.get("username") or result.get("user") or login_identifier
        else:
            user_record = get_users(login_identifier)
            if user_record and len(user_record) > 0 and isinstance(user_record[0], dict):
                uid = user_record[0].get("uid") or user_record[0].get("id") or 0
                user = user_record[0].get("username") or user_record[0].get("user") or login_identifier
            else:
                uid = 0
                user = login_identifier

        token_res = generate_token({"username": user, "uid": uid})
        raw_token = token_res[0] if isinstance(token_res, tuple) else token_res
        s_token = session_token(raw_token)
        session["token"] = s_token
        return jsonify({"message": "Login successful", "token": s_token})
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

if __name__ == "__main__":
    from api.init import db_init
    try:
        db_init()
    except Exception as e:
        print(f"Database init warning: {e}")

    debug_mode = os.getenv("SERVER_DEBUG", "False").lower() in ("true", "1", "yes")
    host_addr = os.getenv("SERVER_HOST", "127.0.0.1") or "127.0.0.1"
    port_env = os.getenv("SERVER_PORT", "5000")
    port_num = int(port_env) if port_env and port_env.isdigit() else 5000
    app.run(debug=debug_mode, host=host_addr, port=port_num)