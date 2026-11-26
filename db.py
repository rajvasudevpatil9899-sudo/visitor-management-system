import mysql.connector
from mysql.connector import Error


def get_db_connection():
    try:
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="system",
            database="visitor_management",
            port=3306
        )
    except Error as e:
        print("Database connection error:", e)
        return None
    

    