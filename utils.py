import mysql.connector
import os
import bcrypt as bc

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME")
    )


def AddUser(username: str, password: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        print(f'Adding user: {username} with password {password}')

        cursor.execute("CALL AddUser(%s, %s);", (username, password))
        conn.commit()
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        cursor.close()
        conn.close()

def CheckUser(username: str, passwordHash: str) -> bool:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        args = (username, None)
        result = cursor.callproc("GetPasswordHash", args)
        retrievedPasswordHash = result[1]
        cursor.close()
        conn.close()
        return bc.checkpw(passwordHash.encode('utf-8'), retrievedPasswordHash.encode('utf-8'))
    except Exception as e:
        print(f"Error occurred: {e}")
        return False

def GetUserID(username: str):
    try:
        print(f'Username: {username}')
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_user FROM user WHERE username=%s;", (username, ))
        result = cursor.fetchone()
        if not result:
            raise LookupError(f"User '{username}' not found in the database.")
        return result['id_user']
    except Exception as e:
        print(f"Error occurred: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def GetUserData(userID: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        args = (userID, None, None, None)
        result = cursor.callproc("GetUserData", args)
        return result
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        cursor.close()
        conn.close()

def GetGender(genderID: int) -> str:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT gender FROM gender WHERE id_gender = %s", (genderID, ))
        result = cursor.fetchone()
        print(result)
        return result[0]
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        cursor.close()
        conn.close()