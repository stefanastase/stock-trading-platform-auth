import os
import psycopg2
import jwt
from datetime import datetime, timedelta
import sys

# Get environment variables
host = os.getenv('HOST_NAME')
auth_db_name = os.getenv('AUTH_DB_NAME')
portfolios_db_name = os.getenv('PORTFOLIOS_DB_NAME')
db_user = os.getenv('DB_USER')
db_pass_file = os.getenv('DB_PASSWORD_FILE')
auth_secret_file = os.getenv('AUTH_SECRET_FILE')
expire_time_seconds = int(os.getenv('EXPIRE_TIME_SEC'))

def register(clientID, clientSecret, isAdmin):
    connection = None

    try:
        file = open(db_pass_file, "r")
        db_pass = file.read() 
        file.close()
        
        connection = psycopg2.connect(host=host, dbname=auth_db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()

        query = "INSERT INTO clients (\"ClientID\", \"ClientSecret\", \"IsAdmin\") VALUES (%s, %s, %s)"

        cursor.execute(query, (clientID, clientSecret, str(isAdmin)))
        connection.commit()
        
        cursor.close()
        connection.close()

        # Create portfolio table for the new client
        connection = psycopg2.connect(host=host, dbname=portfolios_db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()

        create_query = f"\
                CREATE TABLE {clientID} (\
                \"ID\" integer NOT NULL GENERATED ALWAYS AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 100 CACHE 1 ),\
                \"Name\" character varying(128) COLLATE pg_catalog.\"default\" NOT NULL,\
                \"Quantity\" real  NOT NULL,\
                CONSTRAINT {clientID}_pkey PRIMARY KEY (\"ID\"),\
                CONSTRAINT {clientID}_unique UNIQUE (\"Name\"))"

        cursor.execute(create_query)

        # Add empty cash component to newly created table
        insert_query = f"INSERT INTO {clientID} (\"Name\", \"Quantity\") VALUES ('Cash', '0.0')"
        cursor.execute(insert_query)

        grant_query = f"GRANT ALL PRIVILEGES ON {clientID} TO portfolios_user"
        cursor.execute(grant_query)

        connection.commit()

        return True
    
    except (Exception, psycopg2.DatabaseError) as error:
        print(error, file=sys.stderr)
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
        file = open(db_pass_file, "r")
        db_pass = file.read() 
        file.close()

        file = open(auth_secret_file, "r")
        auth_secret = file.read()
        file.close()

        connection = psycopg2.connect(host=host, dbname=auth_db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()
        query = " SELECT * FROM clients WHERE \"ClientID\"='" + clientID + "' AND \"ClientSecret\"='" + clientSecret + "'"
        cursor.execute(query)

        records = cursor.fetchall()

        if cursor.rowcount == 1:
            row = records[0]
            now = datetime.now() + timedelta(seconds=expire_time_seconds)
            payload = {
                "id": row[0],
                "clientID": row[1],
                "expirationTime": now.strftime("%m/%d/%Y, %H:%M:%S")
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

def validate(token):
    connection = None
    try:
        file = open(db_pass_file, "r")
        db_pass = file.read() 
        file.close()
        
        file = open(auth_secret_file, "r")
        auth_secret = file.read()
        file.close()

        connection = psycopg2.connect(host=host, dbname=auth_db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()

        query = f"SELECT * FROM blacklist WHERE \"token\" = \'{token}\'"

        cursor.execute(query)

        records = cursor.fetchall()

        if cursor.rowcount == 0:    
            try:
                decoded_token = jwt.decode(token, auth_secret, algorithms=['HS256'])
                return decoded_token
            except (Exception) as error:
                return None
        else:
            return None
    
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        if connection is not None:
            cursor.close()
            connection.close()

        return None

    finally:
        if connection is not None:
            cursor.close()
            connection.close()

def invalidate(token):
    connection = None
    try:
        file = open(db_pass_file, "r")
        db_pass = file.read() 
        file.close()

        connection = psycopg2.connect(host=host, dbname=auth_db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()

        query = f"INSERT INTO blacklist(\"token\") VALUES (\'{token}\')"

        cursor.execute(query)
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