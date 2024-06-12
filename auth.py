from flask import Flask, render_template, request, redirect, url_for, flash, session
import bcrypt
from config import get_db
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = '123'  # Cambia esto por una clave secreta segura

db = get_db()
users_collection = db['users']
photos_collection = db['photos']

@app.route('/')
def home():
    users = list(users_collection.find())
    return render_template('home.html', users=users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if users_collection.find_one({'username': username}):
            flash('El usuario ya existe', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users_collection.insert_one({
            'username': username,
            'password': hashed_password
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
            return redirect(url_for('home'))

        flash('Usuario o contraseña incorrectos', 'danger')
        return redirect(url_for('login'))

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

@app.route('/profile/<username>')
def profile(username):
    user = users_collection.find_one({'username': username})
    if not user:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('home'))

    photos = list(photos_collection.find({'username': username}))

    return render_template('profile.html', username=username, photos=photos)

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

    return render_template('user_detail.html', user=user, photos=photos)

if __name__ == '__main__':
    app.run(debug=True)