from pymongo import MongoClient

def get_db():
    client = MongoClient('mongodb://localhost:27017/')  # Cambia esta URI si usas MongoDB Atlas
    db = client['mydb']  # Nombre de tu base de datos
    return db

