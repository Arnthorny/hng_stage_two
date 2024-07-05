#!/usr/bin/env python3
"""
Basic Flask app
"""
from flask import Flask
from routes import api_routes
from routes import auth_routes


app = Flask(__name__)
app.register_blueprint(api_routes)
app.register_blueprint(auth_routes)
app.url_map.strict_slashes = False


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
