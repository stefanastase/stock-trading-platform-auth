import os
import json

import psycopg2
import jwt
from datetime import datetime, timedelta

# Get environment variables
host = os.getenv('HOST_NAME')
db_name = os.getenv('DB_NAME')
db_user = os.getenv('DB_USER')
db_pass = os.getenv('DB_PASSWORD')
auth_secret = os.getenv('AUTH_SECRET')
expire_time_seconds = int(os.getenv('EXPIRE_TIME_SEC'))

def register(clientID, clientSecret, isAdmin):
    connection = None

    try:
        connection = psycopg2.connect(host=host, dbname=db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()

        query = f"INSERT INTO clients (\"ClientID\", \"ClientSecret\", \"IsAdmin\") VALUES (%s, %s, %s)"

        cursor.execute(query, (clientID, clientSecret, str(isAdmin)))
        connection.commit()
        
        return True
    
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        if connection is not None:
            cursor.close()
            connection.close()

        return False

    finally:
        if connection is not None:
            cursor.close()
            connection.close()

def authenticate(clientID, clientSecret):
    connection = None

    try:
        connection = psycopg2.connect(host=host, dbname=db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()
        query = " SELECT * FROM clients WHERE \"ClientID\"='" + clientID + "' AND \"ClientSecret\"='" + clientSecret + "'"
        cursor.execute(query)

        records = cursor.fetchall()

        if cursor.rowcount == 1:
            row = records[0]
            payload = {
                "id": row[0],
                "clientID": row[1],
                "expirationTime": str(datetime.utcnow() + timedelta(seconds=expire_time_seconds)) # TODO Change format here
                }
            
            token = jwt.encode(payload, auth_secret, algorithm='HS256')
            
            return {'token': token}

        else:
            return False
        
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        if connection is not None:
            cursor.close()
            connection.close()

        return False

    finally:
        if connection is not None:
            cursor.close()
            connection.close()

def verify(token):
    try:
        decoded_token = jwt.decode(token, auth_secret, algorithms=['HS256'])
        return decoded_token
    except (Exception) as error:
        return None
