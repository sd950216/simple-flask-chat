from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')


# Define User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), nullable=False)


# Define Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    approved = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('messages', lazy=True))


app.app_context().push()
# Create all database tables
db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


messages = [
    {'content': 'Hello, world!', 'approved': True},
    {'content': 'This is a sample message.', 'approved': False},
    {'content': 'Another message here.', 'approved': True},
    # Add more example messages as needed
]


@app.route('/')
@login_required
def index():
    return render_template('index.html', username=current_user.username, messages=messages)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html', error=None)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('register.html', error='Username already exists')

        new_user = User(username=username, password=generate_password_hash(password), role='user')
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))

    return render_template('register.html', error=None)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/send_message', methods=['POST'])
def send_message():
    message = {'content': request.form['message'], 'approved': False}

    messages.append(message)
    # Emit the message to all connected clients
    socketio.emit('new_message', message)
    return jsonify({'message': 'Message sent successfully'})


@app.route('/get_messages')
def get_messages():
    return jsonify({'messages': messages})


@socketio.on('connect')
def handle_connect():
    # Emit the list of messages to the connected client
    emit('message_list', {'messages': messages})


@socketio.event
def my_ping():
    emit('my_pong')


if __name__ == '__main__':
    socketio.run(app, host='192.168.1.11', port=5000, debug=True)
