#!/usr/bin/env python3
"""
Basic Flask app
"""
from flask import Flask
from routes import api_routes
from routes import auth_routes
from os import getenv



app = Flask(__name__)

app.register_blueprint(api_routes)
app.register_blueprint(auth_routes)

app.url_map.strict_slashes = False

app = Flask(__name__)

SECRET_KEY = getenv('FLASK_SECRET_KEY') or 'KEEP_IT_A_SECRET'
print(SECRET_KEY)
app.config['SECRET_KEY'] = SECRET_KEY





if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
