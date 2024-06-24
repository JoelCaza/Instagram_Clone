from pymongo import MongoClient
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def get_db():
    client = MongoClient('mongodb://localhost:27017/')  
    db = client['mydb']  # Nombre de tu base de datos
    return db
