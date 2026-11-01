#Description: 

from api.db import execute_query

def create_tables():
    users_table = """
    CREATE TABLE IF NOT EXISTS users (
        uid SERIAL PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100) NOT NULL,
        c_date DATE NOT NULL
    );
    """
    tokens_table = """
    CREATE TABLE IF NOT EXISTS tokens (
        uid INT NOT NULL,
        md5 VARCHAR(32) NOT NULL,
        cr_date DATE NOT NULL
    );
    """
    try:
        execute_query(users_table)
        execute_query(tokens_table)
        return True
    except Exception as e:
        return f"Error: {e}"

def db_init():
    try:
        query = "SELECT table_name FROM information_schema.tables WHERE table_schema='public';"
        result = execute_query(query)
        if isinstance(result, list):
            existing_tables = set()
            for row in result:
                if isinstance(row, dict):
                    existing_tables.update(row.values())
                elif isinstance(row, (tuple, list)):
                    existing_tables.update(row)
            if "users" not in existing_tables or "tokens" not in existing_tables:
                create_tables()
        else:
            create_tables()
    except Exception as e:
        print(f"Error initializing DB: {e}")