import os
import psycopg2
import jwt
from datetime import datetime, timedelta
from psycopg2.errorcodes import UNIQUE_VIOLATION
from psycopg2 import errors

# Get environment variables
host = os.getenv('HOST_NAME')
auth_db_name = os.getenv('AUTH_DB_NAME')
portfolios_db_name = os.getenv('PORTFOLIOS_DB_NAME')
db_user = os.getenv('DB_USER')
db_pass_file = os.getenv('DB_PASSWORD_FILE')
auth_secret_file = os.getenv('AUTH_SECRET_FILE')
expire_time_seconds = int(os.getenv('EXPIRE_TIME_SEC'))

def register(clientID, clientSecret, isAdmin, logger):
    connection = None

    try:
        file = open(db_pass_file, "r")
        db_pass = file.read() 
        file.close()
        logger.debug("Database password secret file was read.")
        
        connection = psycopg2.connect(host=host, dbname=auth_db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()
        logger.debug("Connection with database established.")
        
        query = "INSERT INTO clients (\"ClientID\", \"ClientSecret\", \"IsAdmin\") VALUES (%s, %s, %s)"

        cursor.execute(query, (clientID, clientSecret, str(isAdmin)))
        connection.commit()

        logger.debug(f"User {clientID} inserted into the clients table.")
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
        logger.debug(f"Table for {clientID}'s portfolio created.")

        # Add empty cash component to newly created table
        insert_query = f"INSERT INTO {clientID} (\"Name\", \"Quantity\") VALUES ('Cash', '0.0')"
        cursor.execute(insert_query)
        logger.debug(f"Portfolio for {clientID} initialized with empty Cash component.")

        grant_query = f"GRANT ALL PRIVILEGES ON {clientID} TO portfolios_user"
        cursor.execute(grant_query)
        logger.debug(f"Privileges on {clientID} to portfolios_user granted.")
        connection.commit()

        return True
    
    except errors.lookup(UNIQUE_VIOLATION) as error:
        logger.error(f"User {clientID} already exists.")
        logger.debug(error)
        
        if connection is not None:
            cursor.close()
            connection.close()
            logger.debug("Connection with database closed.")

        return False       
    except Exception as error:
        logger.debug(error)
        if connection is not None:
            cursor.close()
            connection.close()
            logger.debug("Connection with database closed.")

        return False

    finally:
        if connection is not None:
            cursor.close()
            connection.close()
            logger.debug("Connection with database closed.")

def authenticate(clientID, clientSecret, logger):
    connection = None

    try:
        file = open(db_pass_file, "r")
        db_pass = file.read() 
        file.close()
        logger.debug("Database password secret file was read.")

        file = open(auth_secret_file, "r")
        auth_secret = file.read()
        file.close()
        logger.debug("Auth secret file was read.")

        connection = psycopg2.connect(host=host, dbname=auth_db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()
        logger.debug("Connection with database established.")

        query = " SELECT * FROM clients WHERE \"ClientID\"='" + clientID + "' AND \"ClientSecret\"='" + clientSecret + "'"
        cursor.execute(query)

        logger.debug("Select client query executed.")
        records = cursor.fetchall()

        if cursor.rowcount == 1:
            row = records[0]
            exp_time = datetime.now() + timedelta(seconds=expire_time_seconds)
            logger.debug("Expiration time calculated.")
            payload = {
                "id": row[0],
                "clientID": row[1],
                "expirationTime": exp_time.strftime("%m/%d/%Y, %H:%M:%S")
                }
            logger.info(f"Credentials passed by {clientID} are valid.")
            token = jwt.encode(payload, auth_secret, algorithm='HS256')
            logger.debug("JWT Token created.")
            logger.info("Created token with expiration time "+ exp_time.strftime("%m/%d/%Y, %H:%M:%S"))
            return {'token': token}

        else:
            logger.error(f"Credentials for {clientID} are invalid.")
            return False
        
    except (Exception, psycopg2.DatabaseError) as error:
        logger.debug(error)
        if connection is not None:
            cursor.close()
            connection.close()

        return False

    finally:
        if connection is not None:
            cursor.close()
            connection.close()

def validate(token, logger):
    connection = None
    try:
        file = open(db_pass_file, "r")
        db_pass = file.read() 
        file.close()
        logger.debug("Database password secret file was read.")

        file = open(auth_secret_file, "r")
        auth_secret = file.read()
        file.close()
        logger.debug("Auth secret file was read.")

        connection = psycopg2.connect(host=host, dbname=auth_db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()
        logger.debug("Connection with database established.")

        query = f"SELECT * FROM blacklist WHERE \"token\" = \'{token}\'"

        cursor.execute(query)
        logger.debug("Select from blacklist query executed.")

        records = cursor.fetchall()

        if cursor.rowcount == 0:    
            try:
                decoded_token = jwt.decode(token, auth_secret, algorithms=['HS256'])
                logger.debug(f"Token {token} has been decoded.")
                return decoded_token
            except (Exception) as error:
                logger.error("Provided token could not be decoded.")
                return None
        else:
            logger.error("Provided token is expired.")
            return None
    
    except (Exception, psycopg2.DatabaseError) as error:
        logger.debug(error)
        if connection is not None:
            cursor.close()
            connection.close()

        return None

    finally:
        if connection is not None:
            cursor.close()
            connection.close()

def invalidate(token, logger):
    connection = None
    try:
        file = open(db_pass_file, "r")
        db_pass = file.read() 
        file.close()
        logger.debug("Database password secret file was read.")

        file = open(auth_secret_file, "r")
        auth_secret = file.read()
        file.close()
        logger.debug("Auth secret file was read.")

        connection = psycopg2.connect(host=host, dbname=auth_db_name, user=db_user, password=db_pass)
        cursor = connection.cursor()
        logger.debug("Connection with database established.")

        query = f"INSERT INTO blacklist(\"token\") VALUES (\'{token}\')"

        cursor.execute(query)
        logger.debug(f"Token {token} added to blacklist.")
        connection.commit()

        logger.info(f"Token {token} invalidated.")        
        return jwt.decode(token, auth_secret, algorithms=['HS256']).get('clientID')
    
    except (Exception, psycopg2.DatabaseError) as error:
        logger.debug(error)
        if connection is not None:
            cursor.close()
            connection.close()

        return None

    finally:
        if connection is not None:
            cursor.close()
            connection.close()