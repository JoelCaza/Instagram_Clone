import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_socketio import SocketIO, send, emit, join_room, leave_room
import bcrypt
from config import get_db
from bson.objectid import ObjectId
import base64
from werkzeug.security import check_password_hash
from datetime import datetime

def convert_image_to_base64(image_data):
    return base64.b64encode(image_data).decode('utf-8')

app = Flask(__name__)
app.secret_key = '123'  # Cambia esto por una clave secreta segura
socketio = SocketIO(app, async_mode='eventlet')  # Asegúrate de que async_mode esté configurado como 'eventlet'

db = get_db()
users_collection = db['users']
photos_collection = db['photos']
messages_collection = db['messages']  # Colección para almacenar los mensajes de chat

users_session = {}  # Diccionario para almacenar las sesiones de los usuarios

@app.route('/')
def home():
    users = list(users_collection.find())
    top_photo = photos_collection.find_one(sort=[("likes", -1)])
    return render_template('home.html', users=users, top_photo=top_photo, convert_image_to_base64=convert_image_to_base64)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        profile_image = request.files['profile_image']

        if users_collection.find_one({'username': username}):
            flash('El usuario ya existe', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        if profile_image:
            profile_image_data = profile_image.read()
            profile_image_base64 = convert_image_to_base64(profile_image_data)
        else:
            profile_image_base64 = None

        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'profile_image': profile_image_base64
        })

        flash('Usuario registrado con éxito', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_collection.find_one({'username': username})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = username
            flash('Login exitoso', 'success')
            return redirect(url_for('chat'))

        flash('Usuario o contraseña incorrectos', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Sesión cerrada', 'success')
    return redirect(url_for('home'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        flash('Debes iniciar sesión para subir una foto', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        image = request.files['image']

        if image:
            image_data = image.read()
            photos_collection.insert_one({
                'username': session['username'],
                'title': title,
                'image': image_data,
                'likes': [],
                'comments': []
            })

            flash('Foto subida con éxito', 'success')
            return redirect(url_for('profile', username=session['username']))

    return render_template('upload.html')

@app.route('/profile/<username>', methods=['GET'])
def profile(username):
    user = users_collection.find_one({'username': username})
    if not user:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('home'))
    
    photos = list(photos_collection.find({'username': username}))
    
    return render_template('profile.html', username=username, user=user, photos=photos, convert_image_to_base64=convert_image_to_base64, str=str)

@app.route('/like/<photo_id>', methods=['POST'])
def like(photo_id):
    if 'username' not in session:
        flash('Debes iniciar sesión para dar like', 'danger')
        return redirect(url_for('login'))

    photo = photos_collection.find_one({'_id': ObjectId(photo_id)})
    if not photo:
        flash('Foto no encontrada', 'danger')
        return redirect(url_for('home'))

    if session['username'] not in photo['likes']:
        photos_collection.update_one({'_id': ObjectId(photo_id)}, {'$push': {'likes': session['username']}})
        flash('Foto liked', 'success')
    else:
        flash('Ya has dado like a esta foto', 'info')

    return redirect(url_for('profile', username=photo['username']))

@app.route('/comment/<photo_id>', methods=['POST'])
def comment(photo_id):
    if 'username' not in session:
        flash('Debes iniciar sesión para comentar', 'danger')
        return redirect(url_for('login'))

    photo = photos_collection.find_one({'_id': ObjectId(photo_id)})
    if not photo:
        flash('Foto no encontrada', 'danger')
        return redirect(url_for('home'))

    comment = request.form['comment']
    if comment:
        photos_collection.update_one(
            {'_id': ObjectId(photo_id)},
            {'$push': {'comments': {'username': session['username'], 'comment': comment}}}
        )
        flash('Comentario agregado', 'success')

    return redirect(url_for('profile', username=photo['username']))

@app.route('/user/<username>')
def user_detail(username):
    user = users_collection.find_one({'username': username})
    if not user:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('home'))

    photos = list(photos_collection.find({'username': username}))

    return render_template('user_detail.html', user=user, photos=photos, convert_image_to_base64=convert_image_to_base64)

@app.route('/delete_profile/<username>', methods=['POST'])
def delete_profile(username):
    if 'username' not in session or session['username'] != username:
        flash('No tienes permiso para eliminar este perfil', 'danger')
        return redirect(url_for('home'))

    # Eliminar usuario de la base de datos
    users_collection.delete_one({'username': username})
    # Eliminar todas las fotos del usuario de la base de datos
    photos_collection.delete_many({'username': username})

    # Limpiar la sesión
    session.pop('username', None)
    flash('Perfil eliminado correctamente', 'success')
    return redirect(url_for('home'))

@app.route('/perfil/<username>', methods=['GET'])
def vista_usuario(username):
    posts = list(photos_collection.find({'author': username}))  # Obtener las fotos del usuario
    users = list(users_collection.find().limit(6))  # Ejemplo de obtención de usuarios

    return render_template('vista_user.html', posts=posts, users=users, convert_image_to_base64=convert_image_to_base64)

@app.route('/unlike/<photo_id>', methods=['POST'])
def unlike(photo_id):
    if 'username' not in session:
        flash('Debes iniciar sesión para quitar el like', 'danger')
        return redirect(url_for('login'))

    photo = photos_collection.find_one({'_id': ObjectId(photo_id)})
    if not photo:
        flash('Foto no encontrada', 'danger')
        return redirect(url_for('home'))

    if session['username'] in photo['likes']:
        photos_collection.update_one({'_id': ObjectId(photo_id)}, {'$pull': {'likes': session['username']}})
        flash('Like removido', 'success')
    else:
        flash('No has dado like a esta foto', 'info')

    return redirect(url_for('profile', username=photo['username']))

# Ruta para el chat
@app.route('/chat')
def chat():
    if 'username' not in session:
        flash('Debes iniciar sesión para acceder al chat', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    # Obtener todos los usuarios excepto el usuario actual
    users = list(users_collection.find({'username': {'$ne': username}}))
    return render_template('chat.html', username=username, users=users)

@socketio.on('private_message')
def handle_private_message(data):
    recipient = data['recipient']
    recipient_session_id = users_session.get(recipient)
    if recipient_session_id:
        message = data['message']
        sender = session['username']
        emit('private_message', {'message': message, 'sender': sender, 'recipient': recipient}, room=recipient_session_id)
        # Guardar el mensaje en la base de datos
        messages_collection.insert_one({
            'sender': sender,
            'recipient': recipient,
            'message': message,
            'timestamp': datetime.utcnow()
        })
    # Emitir el mensaje al remitente para que también se muestre en su pantalla
    emit('private_message', {'message': message, 'sender': sender, 'recipient': recipient}, room=request.sid)

@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        users_session[session['username']] = request.sid

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        users_session.pop(session['username'], None)

@app.route('/get_messages/<recipient>', methods=['GET'])
def get_messages(recipient):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    messages = list(messages_collection.find({
        '$or': [
            {'sender': username, 'recipient': recipient},
            {'sender': recipient, 'recipient': username}
        ]
    }).sort('timestamp', 1))
    
    # Formatear los mensajes para que se puedan enviar al cliente
    formatted_messages = [{'sender': msg['sender'], 'recipient': msg['recipient'], 'message': msg['message']} for msg in messages]

    return {'messages': formatted_messages}

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
