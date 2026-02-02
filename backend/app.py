from flask import Flask
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend"))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
app.secret_key = os.getenv("SECRET_KEY")

# Upload folder for all blueprints
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Import Blueprints
from .admin.routes import admin_bp
from .student.routes import student_bp

# Register Blueprints
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(student_bp, url_prefix='/student')

if __name__ == "__main__":
    app.run()
    #python -m backend.app  