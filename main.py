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


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def convert_messages_to_dict():
    messages = Message.query.all()
    return [
        {'content': message.content, 'approved': message.approved, 'username': message.user.username, 'id': message.id}
        for message in
        messages]


@app.route('/')
@login_required
def index():
    messages = convert_messages_to_dict()
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
            login_user(user, remember=True)  # Store the user's session
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
        role = request.form['role']

        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('register.html', error='Username already exists')

        new_user = User(username=username, password=generate_password_hash(password), role=role)
        db.session.add(new_user)
        db.session.commit()
        login_user(user, remember=True)  # Store the user's session
        return redirect(url_for('index'))

    return render_template('register.html', error=None)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/send_message', methods=['POST'])
def send_message():
    if 'message' not in request.form or not request.form['message']:
        return jsonify({'error': 'Message cannot be empty'})

    if current_user.role == 'admin':
        message = {'content': request.form['message'], 'approved': True, 'username': current_user.username,'id':len(Message.query.all())+1}
    else:
        message = {'content': request.form['message'], 'approved': False, 'username': current_user.username,'id':len(Message.query.all())+1}

    new_message = Message(content=message['content'], approved=message['approved'], user_id=current_user.id)
    db.session.add(new_message)
    db.session.commit()

    # Emit the message to all connected clients
    socketio.emit('new_message', message)
    print(message.id)

    return jsonify({'message': 'Message sent successfully'})


@app.route('/get_messages')
def get_messages():
    messages = convert_messages_to_dict()
    return jsonify({'messages': messages})


@socketio.on('connect')
def handle_connect():
    messages = convert_messages_to_dict()
    # Emit the list of messages to the connected client
    emit('message_list', {'messages': messages})


# ... Your other route and import statements ...

@app.route('/approve_messages', methods=['GET', 'POST'])
@login_required
def approve_messages():
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    # Fetch all messages pending approval
    pending_messages = Message.query.filter_by(approved=False).all()

    if request.method == 'POST':
        # Get the list of message IDs to approve
        approved_ids = request.form.getlist('approved_messages[]')
        print(approved_ids)

        # Update the approved status for the selected messages
        for message in pending_messages:
            if str(message.id) in approved_ids:
                message.approved = True

        # Commit the changes to the database
        db.session.commit()

        # Emit the approved messages to connected clients
        approved_messages = Message.query.filter(Message.id.in_(approved_ids)).all()
        for message in approved_messages:
            inner_message = {'message_id': message.id, 'content': message.content, 'username': message.user.username}
            socketio.emit('message_approved', inner_message)

        return jsonify({'message': 'Approved successfully'}), 200

    return render_template('approve_messages.html', messages=pending_messages)


@app.route('/events')
def events():
    return render_template('events-construct.html')


if __name__ == '__main__':
    socketio.run(app, host='192.168.1.4', port=5000, debug=True)
