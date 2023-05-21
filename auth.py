from flask import Flask, request, Response
from json import dumps
import hashlib
from datetime import datetime
import authUtils

from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)

# Route for registration
@app.route("/register", methods=["POST"])
def register():
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")   

    # Get hashed secret using SHA256
    hashed_secret = hashlib.sha256(bytes(client_secret, 'utf-8')).hexdigest()

    registerResult = authUtils.register(client_id, hashed_secret, app.logger)
    
    if registerResult:
        app.logger.info(f"User {client_id} registered into the system.")
        return Response(status=201)
    
    app.logger.error(f"User {client_id} could not be registered.")
    return Response(status=400)

# Route for authentication
@app.route("/login", methods=["POST"])
def login():	
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    # Get hashed secret using SHA256
    hashed_secret = hashlib.sha256(bytes(client_secret, 'utf-8')).hexdigest()

    authResult = authUtils.authenticate(client_id, hashed_secret, app.logger)

    if authResult == False:
        app.logger.error(f"User {client_id} was not authenticated.")
        return Response(status=401)
    else: 
        app.logger.info(f"User {client_id} authenticated succesfully.")
        return Response(dumps(authResult), status=200, mimetype='application/json')

# Route for veryfing JWT
@app.route("/verify", methods=["POST"])
def verify():
    # Get the authorization header
    authorizationHeader = request.headers.get('authorization')
    if authorizationHeader is None:
        app.logger.error("No token provided.")
        return Response(status=400)
    # Remove the 'Bearer ' keyword from authorization header	
    token = authorizationHeader[7:]

    verifyResult = authUtils.validate(token, app.logger)

    if verifyResult is None:
        app.logger.error(f"Token {token} is invalid.")
        return Response(status=401)
    elif datetime.strptime(verifyResult.get('expirationTime'), "%m/%d/%Y, %H:%M:%S") < datetime.utcnow(): 
        # Invalidate token by adding to blacklist
        app.logger.info(f"Token {token} expiration time was " + datetime.strptime(verifyResult.get('expirationTime'), "%m/%d/%Y, %H:%M:%S"))
        invalidateResult = authUtils.invalidate(token, app.logger)

        if not invalidateResult is None:
            app.logger.error(f"Token {token} is no longer valid.")
            return Response(dumps({"error": "Token expired. Please log-in again."}), status=401, mimetype='application/json')

    app.logger.info(f"Token {token} is valid.")    
    return Response(dumps(verifyResult), status=200, mimetype='application/json')

# Route for logging out
@app.route("/logout", methods=["POST"])
def logout():
    # Get the authorization header
    authorizationHeader = request.headers.get('authorization')
    if authorizationHeader is None:
        app.logger.error("No token provided.")
        return Response(status=400)
    # Remove the 'Bearer ' keyword from authorization header	
    token = authorizationHeader[7:]

    # Invalidate token by adding to blacklist
    invalidateResult = authUtils.invalidate(token, app.logger)

    if not invalidateResult is None:
        app.logger.info(f"User {invalidateResult} logged out.")
        return Response(status=200)
    else:
        app.logger.error(f"User could not be logged out.")
        return Response(status=400)


if __name__ == "__main__":
    app.run(debug=False)