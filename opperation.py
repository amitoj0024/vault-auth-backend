from dotenv import load_dotenv
from datetime import datetime
from pathlib import Path

from api.db import execute_query
from api.utils import not_null
from api.token import generate_token

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
load_dotenv()

def auth_user(login, password):
    query = f"SELECT uid, username, email FROM users WHERE (username='{login}' OR email='{login}') AND password='{password}'"
    try:
        result = execute_query(query)
        if isinstance(result, list) and len(result) > 0:
            return result[0]
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def register(data):
    if not isinstance(data, dict):
        return False
    username = not_null(data.get("username"))
    password = not_null(data.get("password"))
    email = not_null(data.get("email"))
    if any(isinstance(val, str) and val.startswith("Error:") for val in [username, password, email]):
        return False

    c_date = datetime.now().strftime("%Y-%m-%d")
    explicit_uid = data.get("uid")

    if explicit_uid is not None:
        query = f"INSERT INTO users (uid, username, password, email, c_date) VALUES ({explicit_uid}, '{username}', '{password}', '{email}', '{c_date}') RETURNING uid"
    else:
        query = f"INSERT INTO users (username, password, email, c_date) VALUES ('{username}', '{password}', '{email}', '{c_date}') RETURNING uid"

    try:
        result = execute_query(query)
        if isinstance(result, str) and result.startswith("Error:"):
            raise Exception(result)

        if isinstance(result, list) and len(result) > 0 and isinstance(result[0], dict):
            created_uid = result[0].get("uid", explicit_uid or 0)
        else:
            created_uid = explicit_uid or 0

        token_res = generate_token(username, created_uid)
        token = token_res[0] if isinstance(token_res, tuple) else token_res

        query2 = f"INSERT INTO tokens (uid, md5, cr_date) VALUES ({created_uid}, '{token}', '{c_date}')"
        result2 = execute_query(query2)
        if isinstance(result2, str) and result2.startswith("Error:"):
            raise Exception(result2)

        return True
    except Exception as e:
        print(f"Error: {e}")
        return False
    
def get_users(data=None):
    if isinstance(data, int):
        query = f"SELECT uid, username, email FROM users WHERE uid={data}"
    elif data is None:
        query = "SELECT uid, username, email FROM users"
    elif isinstance(data, str):
        query = f"SELECT uid, username, email FROM users WHERE username='{data}' OR email='{data}'"
    else:
        return None
    try:
        result = execute_query(query)
        if isinstance(result, list):
            if data is not None and len(result) == 0:
                return None
            return result
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None
