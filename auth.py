from flask import Flask, request, Response
from json import dumps
import hashlib
from datetime import datetime, timedelta

import authUtils

app = Flask(__name__)

# Route for registration
@app.route("/register", methods=["POST"])
def register():
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")   

    # Get hashed secret using SHA256
    hashed_secret = hashlib.sha256(bytes(client_secret, 'utf-8')).hexdigest()

    registerResult = authUtils.register(client_id, hashed_secret, False) # TODO allow admins to add admins on a different route
    
    if registerResult:
        return Response(status=201)
    
    return Response(status=400)

# Route for authentication
@app.route("/login", methods=["POST"])
def login():	
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    # Get hashed secret using SHA256
    hashed_secret = hashlib.sha256(bytes(client_secret, 'utf-8')).hexdigest()

    authResult = authUtils.authenticate(client_id, hashed_secret)

    if authResult == False:
        return Response(status=401)
    else: 
        return Response(dumps(authResult), status=200, mimetype='application/json')

# Route for veryfing JWT
@app.route("/verify", methods=["POST"])
def verify():
    # Get the authorization header
    authorizationHeader = request.headers.get('authorization')
    if authorizationHeader is None:
        return Response(status=400)
    # Remove the 'Bearer ' keyword from authorization header	
    token = authorizationHeader[7:]

    verifyResult = authUtils.validate(token)

    if verifyResult is None:
        return Response(status=401)
    elif datetime.strptime(verifyResult.get('expirationTime'), "%m/%d/%Y, %H:%M:%S") < datetime.utcnow(): 
        # Invalidate token by adding to blacklist
        invalidateResult = authUtils.invalidate(token)

        if invalidateResult:
            return Response(dumps({"error": "Token expired. Please log-in again."}), status=401, mimetype='application/json')
        
    return Response(dumps(verifyResult), status=200, mimetype='application/json')

# Route for logging out
@app.route("/logout", methods=["POST"])
def logout():
    # Get the authorization header
    authorizationHeader = request.headers.get('authorization')
    if authorizationHeader is None:
        return Response(status=400)
    # Remove the 'Bearer ' keyword from authorization header	
    token = authorizationHeader[7:]

    # Invalidate token by adding to blacklist
    invalidateResult = authUtils.invalidate(token)

    if invalidateResult:
        return Response(status=200)
    else:
        return Response(status=400)


if __name__ == "__main__":
    app.run(debug=False)