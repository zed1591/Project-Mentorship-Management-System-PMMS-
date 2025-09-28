#PMMS App:app.py

import os
import re
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_limiter import Limiter
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from datetime import UTC, datetime, timedelta
from functools import wraps
import time  # Import time for rate limiting

from bson.objectid import ObjectId
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_mail import Mail, Message
from flask_moment import Moment  # Import Flask-Moment
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash

class Config:
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    SECRET_KEY = os.getenv('SECRET_KEY', 'a_very_secret_key_that_should_be_long_and_random')
    REGISTRATION_SECRET_KEY = os.getenv('REGISTRATION_SECRET_KEY', 'default_admin_coordinator_secret')
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)

    # Flask-Mail configuration for Gmail
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')  # Your Gmail address
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')  # Your Gmail App Password
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_USERNAME')

    ADMIN_SECRET_ROUTE = os.getenv('ADMIN_SECRET_ROUTE', '/admin/console_dev_default')

app = Flask(__name__)
app.config.from_object(Config)

socketio = SocketIO(app, cors_allowed_origins="*")


@socketio.on('join_chat')
@login_required
def handle_join_chat(data):
    user_id = data['user_id']
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'User {user_id} has entered the room.'}, room=room)
    print(f"User {user_id} joined room {room}")


@socketio.on('send_message')
@login_required
def handle_send_message(data):
    room = data['room']
    sender_id = data['sender_id']
    message_content = data['message']

    # Create and save the message to the database
    chat_message = {
        'room': room,
        'sender_id': ObjectId(sender_id),
        'message': message_content,
        'timestamp': datetime.now(UTC)
    }
    db.chats.insert_one(chat_message)

    # Emit the new message to everyone in the room
    emit('new_message', {
        'sender_id': sender_id,
        'message': message_content,
        'timestamp': chat_message['timestamp'].isoformat()
    }, room=room)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Remove these Flask-Login related lines:
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.role = user_data['role']
        self.user_data = user_data

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.role = user_data['role']
        self.user_data = user_data

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None
    
    
    
    
    
# Replace the existing CSP configuration with this:
csp = {
    'default-src': "'self'",
    'style-src': [
        "'self'",
        "'unsafe-inline'",
        'https://fonts.googleapis.com',
        'https://cdnjs.cloudflare.com'
    ],
    'script-src': [
        "'self'",
        "'unsafe-inline'",
        'https://cdnjs.cloudflare.com',
        'https://kit.fontawesome.com'
    ],
    'font-src': ["'self'", "data:", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
    'img-src': ["'self'", "data:", "https:", "http:"],
    'connect-src': ["'self'", "ws:", "wss:"]
}

Talisman(
    app,
    force_https=True,
    session_cookie_secure=True,
    content_security_policy=csp
)

csrf = CSRFProtect(app)
moment = Moment(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Database Setup with Optimized Indexes ---
client = MongoClient(app.config['MONGO_URI'])
db = client['pmms']


def initialize_database_indexes():
    """Initialize all required database indexes for optimal performance"""
    indexes_config = {
        'chat' :[
            [('project_id', 1), ('timestamp', 1)]
            ],
        'users': [
            [('email', 1), {'unique': True}],
            [('username', 1), {'unique': True}],
            [('role', 1), ('created_at', -1)],
            [('last_login', -1)],
        ],
        'projects': [
            [('mentee_id', 1)],
            [('mentor_id', 1)],
            [('status', 1), ('created_at', -1)],
            [('mentor_id', 1), ('status', 1)],
        ],
        'activity_logs': [
            [('user_id', 1), ('timestamp', -1)],
            [('timestamp', -1)],
            [('action_type', 1), ('timestamp', -1)],
            [('project_id', 1), ('timestamp', -1)],
        ]
    }
    
    for collection_name, index_specs in indexes_config.items():
        for index_spec in index_specs:
            try:
                # Handle both simple lists and dicts with options
                if isinstance(index_spec[-1], dict):
                    keys = index_spec[0]
                    options = index_spec[1]
                    db[collection_name].create_index(keys, **options)
                else:
                    db[collection_name].create_index(index_spec)
                print(f"✅ Created index on {collection_name}: {index_spec}")
            except Exception as e:
                print(f"⚠️ Failed to create index on {collection_name}: {e}")

# initialize indexes when app starts
initialize_database_indexes()

def get_user_by_id(user_id):
    """Get user by ID for use in templates"""
    try:
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if user:
            return {
                'id': str(user['_id']),
                'username': user.get('username', ''),
                'email': user.get('email', ''),
                'role': user.get('role', '')
            }
        return None
    except Exception as e:
        app.logger.error(f"Error getting user by ID {user_id}: {e}")
        return None


# Add this before your existing context processor
@app.context_processor
def inject_now():
    """Inject current datetime into all templates as 'now'"""
    return {'now': datetime.utcnow()}


@app.context_processor
def inject_user_data():
    """Inject user data into all templates"""
    user_data = {}
    if 'user_id' in session:
        try:
            user = db.users.find_one({'_id': ObjectId(session['user_id'])})
            if user:
                user_data['current_user'] = {
                    'id': str(user['_id']),
                    'username': user.get('username', ''),
                    'email': user.get('email', ''),
                    'role': user.get('role', '')
                }
        except Exception as e:
            app.logger.error(f"Error loading user data for template: {e}")
    
    # Make sure we always return a dictionary
    return user_data

app.jinja_env.globals['get_user_by_id'] = get_user_by_id

def log_activity(user_id, action_type, description, project_id=None, task_id=None):
    """Logs an activity to the system activity log."""
    log = {
        'user_id': ObjectId(user_id),
        'action_type': action_type,
        'description': description,
        'timestamp': datetime.now(UTC)
    }
    if project_id:
        log['project_id'] = ObjectId(project_id)
    if task_id:
        log['task_id'] = ObjectId(task_id)
    db.activity_logs.insert_one(log)

# --- Decorators for Authentication and Authorization ---

def sanitize_input(input_string, max_length=500):
    """Sanitize user input to prevent XSS and injection attacks"""
    if not input_string:
        return ""
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\'&]', '', input_string)
    
    # Truncate to max length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def login_required(f):
    """A decorator to protect routes that require user authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    """
    A decorator to restrict routes to specific user roles.
    Can accept a single role string or a list/tuple of roles.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                return redirect(url_for('login'))
            user = db.users.find_one({'_id': ObjectId(user_id)})
            
            # Allow for a single role string or a list/tuple of roles
            allowed_roles = [roles] if isinstance(roles, str) else roles
            
            if user and user.get('role') in allowed_roles:
                return f(*args, **kwargs)
            else:
                abort(403) # Forbidden
        return decorated_function
    return decorator

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/upload/<project_id>', methods=['POST'])
@login_required
def upload_file(project_id):
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Create project-specific folder
        project_folder = os.path.join(app.config['UPLOAD_FOLDER'], project_id)
        os.makedirs(project_folder, exist_ok=True)
        
        filepath = os.path.join(project_folder, filename)
        file.save(filepath)
        
        # Save to database
        file_doc = {
            'project_id': ObjectId(project_id),
            'filename': filename,
            'original_name': file.filename,
            'filepath': filepath,
            'uploaded_by': ObjectId(session['user_id']),
            'uploaded_at': datetime.now(UTC),
            'file_size': os.path.getsize(filepath)
        }
        
        db.project_files.insert_one(file_doc)
        
        return jsonify({'message': 'File uploaded successfully', 'filename': filename})
    
    return jsonify({'error': 'File type not allowed'}), 400
# --- Rate Limited Routes ---
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = db.users.find_one({'username': username})

        if user and check_password_hash(user.get('password_hash', ''), password):
            session.permanent = True
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['role'] = user['role']
            db.users.update_one({'_id': user['_id']}, {'$set': {'last_login': datetime.now(UTC)}})
            log_activity(user['_id'], 'User Login', 'User logged in successfully.')
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password.'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        full_name = request.form.get('full_name')

        if not all([username, email, password, role, full_name]):
            error = "Please fill out all required fields."
            return render_template('register.html', error=error)
        
        if len(username) < 3 or len(username) > 20:
            error = "Username must be between 3 and 20 characters."
            return render_template('register.html', error=error)

        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            error = "Invalid email address."
            return render_template('register.html', error=error)

        if len(password) < 6:
            error = "Password must be at least 6 characters long."
            return render_template('register.html', error=error)
        
        if db.users.find_one({'$or': [{'username': username}, {'email': email}]}):
            error = "Username or email already exists."
            return render_template('register.html', error=error)
        
        password_hash = generate_password_hash(password)
        created_at = datetime.now(UTC)

        new_user = {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'role': role,
            'profile': {'full_name': full_name},
            'created_at': created_at,
            'last_login': None
        }
        
        if role == 'Mentor':
            new_user['profile']['years_experience'] = request.form.get('years_experience')
            new_user['profile']['availability'] = request.form.get('availability')
        elif role == 'Mentee':
            new_user['profile']['skills'] = request.form.get('skills')
            new_user['profile']['interests'] = request.form.get('interests')
            new_user['profile']['goals'] = request.form.get('goals')

        db.users.insert_one(new_user)
        flash(f"Account for {username} created successfully! You can now log in.", "success")
        return redirect(url_for('login'))
        
    return render_template('register.html', error=error)

@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = db.users.find_one({'email': email})
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[email])
            msg.body = f"Hello,\n\nTo reset your password, visit the following link: {reset_link}\n\nThis link will expire in one hour.\nIf you did not request this, please ignore this email.\n\nThank you,\nPMMS Team"
            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email address.', 'success')
            except Exception as e:
                app.logger.error(f"Mail sending failed: {e}")
                flash('An error occurred while sending the email. Please try again later.', 'danger')
        else:
            flash('No account found with that email address.', 'warning')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

# --- Main Routes (Public and Authentication) ---
@app.route('/api/advanced-analytics')
@login_required
@role_required(['Administrator', 'Coordinator'])
def get_advanced_analytics():
    # Project completion rates by month
    pipeline = [
        {
            '$match': {
                'status': 'Completed',
                'created_at': {'$gte': datetime.now(UTC) - timedelta(days=365)}
            }
        },
        {
            '$group': {
                '_id': {
                    'year': {'$year': '$created_at'},
                    'month': {'$month': '$created_at'}
                },
                'completed_count': {'$sum': 1}
            }
        },
        {'$sort': {'_id.year': 1, '_id.month': 1}}
    ]
    
    monthly_stats = list(db.projects.aggregate(pipeline))
    
    # Mentor performance metrics
    mentor_performance = list(db.projects.aggregate([
        {
            '$match': {'mentor_id': {'$ne': None}}
        },
        {
            '$group': {
                '_id': '$mentor_id',
                'total_projects': {'$sum': 1},
                'completed_projects': {
                    '$sum': {'$cond': [{'$eq': ['$status', 'Completed']}, 1, 0]}
                },
                'avg_completion_time': {'$avg': '$completion_days'}
            }
        }
    ]))
    
    return jsonify({
        'monthly_completion': monthly_stats,
        'mentor_performance': mentor_performance
    })
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/logout')
@login_required
def logout():
    log_activity(session['user_id'], 'User Logout', 'User logged out.')
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('index'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    error = None
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or password != confirm_password:
            error = 'Passwords must match and cannot be empty.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters long.'
        else:
            hashed_password = generate_password_hash(password)
            db.users.update_one({'email': email}, {'$set': {'password_hash': hashed_password}})
            user = db.users.find_one({'email': email})
            if user:
                log_activity(user['_id'], 'Password Reset', 'User successfully reset their password.')
            flash('Your password has been reset successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
            
    return render_template('reset_password.html', token=token, error=error)

# --- Dashboard and User Profile Routes ---
@app.route('/dashboard')
@login_required
def dashboard():
    user = db.users.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        session.clear()
        return redirect(url_for('login'))

    role = user.get('role')

    if role == 'Administrator':
        users = list(db.users.find({}))
        projects = list(db.projects.find({}))
        return render_template('dashboard_admin.html', user=user, users=users, projects=projects)

    elif role == 'Coordinator':
        projects = list(db.projects.find({}))
        for project in projects:
            mentee = get_user_by_id(project.get('mentee_id'))
            mentor = get_user_by_id(project.get('mentor_id'))
            project['mentee_username'] = mentee.get('username') if mentee else 'N/A'
            project['mentor_username'] = mentor.get('username') if mentor else 'Unassigned'
        mentors = list(db.users.find({'role': 'Mentor'}))
        mentees = list(db.users.find({'role': 'Mentee'}))
        return render_template('dashboard_coordinator.html', user=user, projects=projects, mentors=mentors, mentees=mentees)

    elif role == 'Mentor':
        mentor_id = user['_id']
        assigned_projects = list(db.projects.find({'mentor_id': mentor_id}))
        
        mentee_ids = [p.get('mentee_id') for p in assigned_projects if p.get('mentee_id')]
        mentees_under_mentor = []
        if mentee_ids:
             mentees_under_mentor = list(db.users.find({'_id': {'$in': mentee_ids}}))

        return render_template('dashboard_mentor.html', user=user, assigned_projects=assigned_projects, mentees_under_mentor=mentees_under_mentor)

    elif role == 'Mentee':
        assigned_project = db.projects.find_one({'mentee_id': user['_id']})
        return render_template('dashboard_mentee.html', user=user, assigned_project=assigned_project)

    else:
        abort(403)

@app.route(app.config['ADMIN_SECRET_ROUTE'])
@login_required
@role_required('Administrator')
def admin_console():
    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})
    
    total_users = db.users.count_documents({})
    total_projects = db.projects.count_documents({})
    recent_activity = list(db.activity_logs.find().sort('timestamp', -1).limit(10))
    
    return render_template('admin_console.html', 
                         user=user,
                         total_users=total_users,
                         total_projects=total_projects,
                         recent_activity=recent_activity)
@app.route('/api/notifications/<user_id>')
@login_required
def get_notifications(user_id):
    notifications = list(db.notifications.find({
        'user_id': ObjectId(user_id),
        'read': False
    }).sort('created_at', -1).limit(10))
    
    for notification in notifications:
        notification['_id'] = str(notification['_id'])
        notification['created_at'] = notification['created_at'].isoformat()
    
    return jsonify(notifications)

@socketio.on('join')
def handle_join(data):
    user_id = data['user_id']
    join_room(user_id)

def send_notification(user_id, title, message, type='info'):
    notification = {
        'user_id': ObjectId(user_id),
        'title': title,
        'message': message,
        'type': type,
        'read': False,
        'created_at': datetime.now(UTC)
    }
    
    db.notifications.insert_one(notification)
    
    # Send via SocketIO
    socketio.emit('new_notification', {
        'title': title,
        'message': message,
        'type': type
    }, room=user_id)
@app.route('/activity_logs')
@login_required
@role_required('Administrator')
def activity_logs_page():
    page = request.args.get('page', 1, type=int)
    per_page = 25
    logs_cursor = db.activity_logs.find().sort('timestamp', -1).skip((page - 1) * per_page).limit(per_page)
    logs = list(logs_cursor)
    
    return render_template('activity_logs.html', logs=logs)

# --- Project Management Routes ---
@app.route('/project/<project_id>')
@login_required
def project_workspace(project_id):
    project = db.projects.find_one({'_id': ObjectId(project_id)})
    if not project:
        abort(404)
        
    user_id = session.get('user_id')
    user_role = session.get('role')
    if not (user_role in ['Administrator', 'Coordinator'] or \
            str(project.get('mentee_id')) == user_id or \
            str(project.get('mentor_id')) == user_id):
        abort(403)
    
    return render_template('project_workspace.html', project=project)

@app.route('/api/create_project', methods=['POST'])
@login_required
@role_required(['Coordinator', 'Mentee'])
def create_project():
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
    
    user_role = session.get('role')
    
    try:
        new_project = {
            'title': data.get('title'),
            'description': data.get('description'),
            'status': 'Proposed',
            'tasks': [],
            'feedback': [],
            'created_at': datetime.now(UTC)
        }

        if user_role == 'Mentee':
            new_project['mentee_id'] = ObjectId(session['user_id'])
            new_project['mentor_id'] = None
        elif user_role == 'Coordinator':
            if not data.get('mentee_id'):
                 return jsonify({'message': 'Mentee ID is required for Coordinator.'}), 400
            new_project['mentee_id'] = ObjectId(data.get('mentee_id'))
            new_project['mentor_id'] = ObjectId(data.get('mentor_id')) if data.get('mentor_id') else None

        if not new_project.get('title') or not new_project.get('description'):
            return jsonify({'message': 'Title and description are required.'}), 400
        
        result = db.projects.insert_one(new_project)
        log_activity(session['user_id'], 'Project Creation', f'New project "{new_project["title"]}" created.', project_id=result.inserted_id)
        return jsonify({'message': 'Project created successfully!'}), 201

    except Exception as e:
        app.logger.error(f"Error creating project: {e}")
        return jsonify({'message': f'An error occurred: {e}'}), 500
# --- Search Functionality ---
@app.route('/search', methods=['GET', 'POST'])
@login_required
@role_required(['Administrator', 'Coordinator', 'Mentor'])
def search_page():
    if request.method == 'POST':
        query = request.form.get('query')
        search_results = []
        if query:
            users_results = list(db.users.find({
                '$or': [
                    {'first_name': {'$regex': query, '$options': 'i'}},
                    {'last_name': {'$regex': query, '$options': 'i'}},
                    {'email': {'$regex': query, '$options': 'i'}}
                ]
            }))
            search_results.extend(users_results)
            
            projects_results = list(db.projects.find({
                '$or': [
                    {'title': {'$regex': query, '$options': 'i'}},
                    {'description': {'$regex': query, '$options': 'i'}}
                ]
            }))
            search_results.extend(projects_results)
        
        return render_template('search.html', results=search_results)

    try:
        available_mentees = list(db.users.find({'role': 'Mentee', 'status': 'available'}))
    except Exception as e:
        flash(f"Error loading available mentees: {e}")
        available_mentees = []

    return render_template('search.html', available_mentees=available_mentees)

# --- API Endpoints ---
@app.route('/api/users/<user_id>', methods=['DELETE'])
@login_required
@role_required('Administrator')
def delete_user(user_id):
    if str(session['user_id']) == user_id:
        return jsonify({'message': 'Cannot delete your own admin account.'}), 400
    try:
        result = db.users.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count == 1:
            log_activity(session['user_id'], 'User Deletion', f'Admin deleted user with ID: {user_id}.')
            return jsonify({'message': 'User deleted successfully'}), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        app.logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({'message': f'An error occurred: {e}'}), 500

@app.route('/create_project_page')
@login_required
@role_required(['Coordinator', 'Mentee'])
def create_project_page():
    user_role = session.get('role')
    if user_role == 'Mentee':
        return render_template('create_project.html')
    elif user_role == 'Coordinator':
        mentees = list(db.users.find({'role': 'Mentee'}))
        mentors = list(db.users.find({'role': 'Mentor'}))
        return render_template('create_project_coordinator.html', mentees=mentees, mentors=mentors)
    return abort(403)
@app.route('/api/projects/<project_id>/tasks', methods=['POST'])
@login_required
@role_required('Mentor')
def add_task(project_id):
    task_data = request.json
    task_name = task_data.get('task_name')
    if not task_name:
        return jsonify({'message': 'Task name is required'}), 400
    new_task = {
        '_id': str(ObjectId()),
        'name': task_name,
        'description': task_data.get('task_description', ''),
        'completed': False
    }
    db.projects.update_one({'_id': ObjectId(project_id)}, {'$push': {'tasks': new_task}})
    log_activity(session['user_id'], 'Task Addition', f'New task "{task_name}" added.', project_id=project_id, task_id=new_task['_id'])
    return jsonify({'message': 'Task added successfully', 'task_id': new_task['_id']}), 201

@app.route('/api/projects/<project_id>/tasks/<task_id>', methods=['PATCH'])
@login_required
@role_required(['Mentee', 'Mentor'])
def update_task_status(project_id, task_id):
    data = request.json
    new_status = data.get('completed', False)
    result = db.projects.update_one(
        {'_id': ObjectId(project_id), 'tasks._id': task_id},
        {'$set': {'tasks.$.completed': new_status}}
    )
    if result.modified_count:
        action_desc = f'Task status updated to {"Completed" if new_status else "Incomplete"}.'
        log_activity(session['user_id'], 'Task Update', action_desc, project_id=project_id, task_id=task_id)
        return jsonify({'message': 'Task status updated successfully'}), 200
    return jsonify({'message': 'Task not found or status unchanged'}), 404
@app.route('/api/projects/<project_id>', methods=['GET'])
@login_required
def get_project_details(project_id):
    try:
        project = db.projects.find_one({'_id': ObjectId(project_id)})
        if not project:
            return jsonify({'message': 'Project not found.'}), 404
        
        # Convert ObjectId and datetime objects to strings
        project_data = {
            '_id': str(project['_id']),
            'title': project.get('title', ''),
            'description': project.get('description', ''),
            'status': project.get('status', 'Proposed'),
            'mentee_id': str(project.get('mentee_id', '')),
            'mentor_id': str(project.get('mentor_id', '')) if project.get('mentor_id') else None,
            'created_at': project.get('created_at', datetime.now(UTC)).isoformat(),
            'tasks': [],
            'feedback': []
        }
        
        # Handle tasks
        for task in project.get('tasks', []):
            task_data = {
                '_id': str(task.get('_id', '')),
                'name': task.get('name', ''),
                'description': task.get('description', ''),
                'completed': task.get('completed', False)
            }
            project_data['tasks'].append(task_data)
        
        # Handle feedback
        for feedback in project.get('feedback', []):
            feedback_data = {
                'mentor_id': str(feedback.get('mentor_id', '')),
                'rating': feedback.get('rating', 0),
                'comments': feedback.get('comments', ''),
                'timestamp': feedback.get('timestamp', datetime.now(UTC)).isoformat()
            }
            project_data['feedback'].append(feedback_data)
        
        return jsonify(project_data), 200

    except Exception as e:
        app.logger.error(f"Error fetching project details: {e}")
        return jsonify({'message': 'An error occurred while fetching project details.'}), 500
@app.route('/api/activity_logs', methods=['GET'])
@login_required
@role_required('Administrator')
def get_activity_logs_api():
    try:
        # Fetch logs with user information
        pipeline = [
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'user_id',
                    'foreignField': '_id',
                    'as': 'user_info'
                }
            },
            {
                '$sort': {'timestamp': -1}
            },
            {
                '$limit': 100  # Limit to recent 100 logs
            }
        ]
        
        logs_cursor = db.activity_logs.aggregate(pipeline)
        logs = list(logs_cursor)

        formatted_logs = []
        for log in logs:
            log_data = {
                '_id': str(log['_id']),
                'timestamp': log['timestamp'].isoformat(),
                'action_type': log.get('action_type', ''),
                'description': log.get('description', ''),
                'user_id': str(log['user_id']) if log.get('user_id') else None
            }
            
            # Add user information if available
            if log.get('user_info'):
                user = log['user_info'][0]
                log_data['username'] = user.get('username', 'Unknown')
                log_data['user_role'] = user.get('role', 'Unknown')
            
            # Add project/task info if available
            if log.get('project_id'):
                log_data['project_id'] = str(log['project_id'])
            if log.get('task_id'):
                log_data['task_id'] = str(log['task_id'])
                
            formatted_logs.append(log_data)
        
        return jsonify(formatted_logs)

    except Exception as e:
        app.logger.error(f"Error fetching activity logs API: {e}")
        return jsonify({"message": "Failed to load activity logs."}), 500

@app.route('/api/mentor_match', methods=['POST'])
@login_required
@role_required('Coordinator')
def mentor_match():
    data = request.json
    project_id = data.get('project_id')
    mentor_id = data.get('mentor_id')
    if not project_id or not mentor_id:
        return jsonify({"message": "Project ID and Mentor ID are required."}), 400
    try:
        project_oid, mentor_oid = ObjectId(project_id), ObjectId(mentor_id)
        mentor = db.users.find_one({'_id': mentor_oid})
        if not mentor:
            return jsonify({"message": "Mentor not found."}), 404
        result = db.projects.update_one(
            {'_id': project_oid},
            {'$set': {'mentor_id': mentor_oid, 'status': 'In Progress'}}
        )
        if result.modified_count == 1:
            log_activity(session['user_id'], 'Mentor Assignment', f'Assigned mentor {mentor["username"]} to project {project_id}.', project_id=project_id)
            return jsonify({"message": "Mentor assigned successfully!"}), 200
        else:
            return jsonify({"message": "Project not found or no changes made."}), 404
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/api/available_mentors')
@login_required
@role_required(['Administrator', 'Coordinator'])
def get_available_mentors():
    mentors = list(db.users.find({'role': 'Mentor'}, {'password_hash': 0}))
    for mentor in mentors:
        mentor['_id'] = str(mentor['_id'])
    return jsonify(mentors)

@app.route('/api/mentees_list')
@login_required
@role_required(['Administrator', 'Coordinator'])
def get_mentees_list():
    mentees = list(db.users.find({'role': 'Mentee'}, {'password_hash': 0}))
    for mentee in mentees:
        mentee['_id'] = str(mentee['_id'])
    return jsonify(mentees)

#
@app.route('/api/mentee/<mentee_id>/gantt_data')
@login_required
@role_required(['Mentee', 'Administrator', 'Coordinator'])
def get_mentee_gantt_data(mentee_id):
    """API endpoint to get Gantt chart data for a specific mentee"""
    try:
        # Get all projects for this mentee
        projects = list(db.projects.find({'mentee_id': ObjectId(mentee_id)}))
        
        gantt_data = []
        
        for project in projects:
            project_id = str(project['_id'])
            project_title = project.get('title', 'Untitled Project')
            
            # Add project as a main task
            gantt_data.append([
                f"project_{project_id}",
                project_title,
                "Project",
                project.get('created_at', datetime.now(UTC)),
                project.get('due_date') or (datetime.now(UTC) + timedelta(days=30)),
                0,  # Duration will be calculated by dates
                50 if project.get('status') == 'In Progress' else 
                100 if project.get('status') == 'Completed' else 0,
                ""  # No dependencies
            ])
            
            # Add tasks for this project
            for task in project.get('tasks', []):
                task_id = task.get('_id', '')
                gantt_data.append([
                    f"task_{task_id}",
                    task.get('name', 'Unnamed Task'),
                    "Task",
                    project.get('created_at', datetime.now(UTC)),
                    (project.get('created_at', datetime.now(UTC)) + timedelta(days=7)),
                0,  # Duration will be calculated by dates
                100 if task.get('completed') else 0,
                f"project_{project_id}"  # Dependent on project
                ])
        
        return jsonify(gantt_data)
        
    except Exception as e:
        app.logger.error(f"Error fetching mentee Gantt data: {e}")
        return jsonify({"error": "Failed to load Gantt chart data"}), 500
@app.route('/api/debug/analytics')
@login_required
@role_required(['Administrator', 'Coordinator'])
def debug_analytics():
    try:
        user_counts = {}
        for role in ['Administrator', 'Coordinator', 'Mentor', 'Mentee']:
            count = db.users.count_documents({'role': role})
            user_counts[role] = count
        
        project_counts = {}
        for status in ['Proposed', 'In Progress', 'Completed', 'On Hold']:
            count = db.projects.count_documents({'status': status})
            project_counts[status] = count
        
        return jsonify({
            'user_counts': user_counts,
            'project_counts': project_counts,
            'total_users': db.users.count_documents({}),
            'total_projects': db.projects.count_documents({}),
            'database_status': 'Connected' if db.command('ping') else 'Disconnected'
        })
    except Exception as e:
        return jsonify({"error": str(e), "type": type(e).__name__}), 500

@app.route('/api/debug/indexes')
@login_required
@role_required('Administrator')
def debug_indexes():
    """Debug endpoint to check index usage"""
    collections = ['users', 'projects', 'activity_logs']
    index_info = {}
    
    for collection in collections:
        index_info[collection] = {
            'indexes': list(db[collection].list_indexes()),
            'stats': db.command('collstats', collection)
        }
    
    return jsonify(index_info)

# --- Additional Routes ---
@app.route('/dashboard/<role>')
@login_required
def dashboard_by_role(role):
    user = db.users.find_one({'_id': ObjectId(session['user_id'])})
    if not user or user.get('role') != role:
        abort(403)
    return render_template(f'dashboard_{role.lower()}.html', user=user)

@app.route('/profile/<user_id>', methods=['GET', 'POST'])
@login_required
@role_required('Administrator')
def admin_edit_user_profile(user_id):
    user_to_edit = db.users.find_one({'_id': ObjectId(user_id)})
    if not user_to_edit:
        flash("User not found.", "danger")
        return redirect(url_for('dashboard'))

    error = None

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        if not full_name or len(full_name) < 2 or len(full_name) > 100:
            error = 'Full name must be between 2 and 100 characters.'
        else:
            profile_updates = user_to_edit.get('profile', {})
            profile_updates['full_name'] = full_name
            db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'profile': profile_updates}})
            flash('User profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('admin_edit_user_profile.html', user=user_to_edit, error=error)
@app.route('/api/summary_analytics')
@login_required
@role_required(['Administrator', 'Coordinator'])
def get_summary_analytics():
    """Get dashboard analytics - FIXED VERSION"""
    try:
        # User counts by role
        mentor_count = db.users.count_documents({'role': 'Mentor'})
        mentee_count = db.users.count_documents({'role': 'Mentee'})
        admin_count = db.users.count_documents({'role': 'Administrator'})
        
        # Project counts
        total_projects = db.projects.count_documents({})
        completed_projects = db.projects.count_documents({'status': 'Completed'})
        completion_rate = (completed_projects / total_projects) * 100 if total_projects > 0 else 0
        
        # Project status distribution
        status_counts = list(db.projects.aggregate([
            {'$group': {'_id': '$status', 'count': {'$sum': 1}}}
        ]))
        
        projects_by_status = {}
        for item in status_counts:
            projects_by_status[item['_id']] = item['count']
        
        # Ensure all statuses are present
        for status in ['Proposed', 'In Progress', 'Completed', 'On Hold']:
            if status not in projects_by_status:
                projects_by_status[status] = 0
        
        summary = {
            'users_by_role': {
                'Mentor': mentor_count,
                'Mentee': mentee_count,
                'Administrator': admin_count
            },
            'projects_by_status': projects_by_status,
            'total_projects': total_projects,
            'completion_rate': round(completion_rate, 1)
        }
        
        return jsonify(summary)
        
    except Exception as e:
        app.logger.error(f"Error fetching analytics: {e}")
        return jsonify({"error": "Failed to load analytics"}), 500
# Add these new API endpoints to your app.py

@app.route('/api/mentor_performance')
@login_required
@role_required(['Administrator', 'Coordinator'])
def get_mentor_performance():
    """Get mentor performance ratings from feedback"""
    try:
        pipeline = [
            {
                '$unwind': '$feedback'
            },
            {
                '$group': {
                    '_id': '$mentor_id',
                    'avg_rating': {'$avg': '$feedback.mentor_rating'},
                    'total_feedbacks': {'$sum': 1}
                }
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': '_id',
                    'foreignField': '_id',
                    'as': 'mentor_info'
                }
            },
            {
                '$unwind': '$mentor_info'
            },
            {
                '$project': {
                    'mentor_name': '$mentor_info.username',
                    'avg_rating': {'$ifNull': ['$avg_rating', 0]},
                    'total_feedbacks': 1
                }
            }
        ]
        
        mentor_performance = list(db.projects.aggregate(pipeline))
        return jsonify(mentor_performance)
    except Exception as e:
        app.logger.error(f"Error fetching mentor performance: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/mentee_satisfaction')
@login_required
@role_required(['Administrator', 'Coordinator'])
def get_mentee_satisfaction():
    """Get mentee satisfaction ratings"""
    try:
        pipeline = [
            {
                '$unwind': '$feedback'
            },
            {
                '$group': {
                    '_id': '$mentee_id',
                    'avg_satisfaction': {'$avg': '$feedback.mentee_satisfaction'},
                    'total_feedbacks': {'$sum': 1}
                }
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': '_id',
                    'foreignField': '_id',
                    'as': 'mentee_info'
                }
            },
            {
                '$unwind': '$mentee_info'
            },
            {
                '$project': {
                    'mentee_name': '$mentee_info.username',
                    'avg_satisfaction': {'$ifNull': ['$avg_satisfaction', 0]},
                    'total_feedbacks': 1
                }
            }
        ]
        
        mentee_satisfaction = list(db.projects.aggregate(pipeline))
        return jsonify(mentee_satisfaction)
    except Exception as e:
        app.logger.error(f"Error fetching mentee satisfaction: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/completion_timeline')
@login_required
@role_required(['Administrator', 'Coordinator'])
def get_completion_timeline():
    """Get project completion timeline for last 6 months"""
    try:
        six_months_ago = datetime.now(UTC) - timedelta(days=180)
        
        pipeline = [
            {
                '$match': {
                    'status': 'Completed',
                    'completed_at': {'$gte': six_months_ago}
                }
            },
            {
                '$group': {
                    '_id': {
                        'year': {'$year': '$completed_at'},
                        'month': {'$month': '$completed_at'}
                    },
                    'completions': {'$sum': 1}
                }
            },
            {
                '$sort': {'_id.year': 1, '_id.month': 1}
            }
        ]
        
        timeline_data = list(db.projects.aggregate(pipeline))
        return jsonify(timeline_data)
    except Exception as e:
        app.logger.error(f"Error fetching completion timeline: {e}")
        return jsonify({"error": str(e)}), 500

# Add these corrected API endpoints to your app.py

@app.route('/api/project_ratings')
@login_required
@role_required(['Administrator', 'Coordinator'])
def get_project_ratings():
    """Get ratings for all projects - FIXED VERSION"""
    try:
        # Get all projects with populated mentor/mentee info
        projects = list(db.projects.find({}))
        
        projects_with_ratings = []
        
        for project in projects:
            # Get mentee info
            mentee = db.users.find_one({'_id': project.get('mentee_id')})
            mentee_username = mentee.get('username', 'N/A') if mentee else 'N/A'
            
            # Get mentor info
            mentor_username = 'Unassigned'
            if project.get('mentor_id'):
                mentor = db.users.find_one({'_id': project.get('mentor_id')})
                mentor_username = mentor.get('username', 'N/A') if mentor else 'N/A'
            
            # Calculate completion percentage
            tasks = project.get('tasks', [])
            completed_tasks = len([t for t in tasks if t.get('completed')])
            completion_percentage = (completed_tasks / len(tasks)) * 100 if tasks else 0
            
            # Calculate average rating from feedback
            feedback_list = project.get('feedback', [])
            ratings = [f.get('mentor_rating', 0) for f in feedback_list if f.get('mentor_rating')]
            avg_rating = sum(ratings) / len(ratings) if ratings else 0
            
            project_data = {
                '_id': str(project['_id']),
                'title': project.get('title', 'Untitled Project'),
                'status': project.get('status', 'Proposed'),
                'mentee_username': mentee_username,
                'mentor_username': mentor_username,
                'created_at': project.get('created_at', datetime.now(UTC)),
                'rating': round(avg_rating, 1),
                'completion_percentage': round(completion_percentage, 1)
            }
            
            projects_with_ratings.append(project_data)
        
        return jsonify(projects_with_ratings)
        
    except Exception as e:
        app.logger.error(f"Error fetching project ratings: {e}")
        return jsonify({"error": "Failed to load projects"}), 500
@app.route('/project/<project_id>/gantt')
@login_required
@role_required(['Administrator', 'Coordinator', 'Mentor', 'Mentee'])
def gantt_chart(project_id):
    project = db.projects.find_one({'_id': ObjectId(project_id)})
    if not project:
        abort(404)

    user_id = session.get('user_id')
    user_role = session.get('role')
    if not (user_role in ['Administrator', 'Coordinator'] or \
            str(project.get('mentee_id')) == user_id or \
            str(project.get('mentor_id')) == user_id):
        abort(403)

    return render_template('gantt_chart.html', project=project)

# Replace with this proper CSP configuration:
@app.route('/api/assign_mentor', methods=['POST'])
@login_required
@role_required(['Administrator', 'Coordinator'])
def assign_mentor():
    """Assign mentor to project - FIXED VERSION"""
    try:
        data = request.get_json()
        project_id = data.get('project_id')
        mentor_id = data.get('mentor_id')
        
        if not project_id or not mentor_id:
            return jsonify({"error": "Project ID and Mentor ID are required"}), 400
        
        # Check if project exists
        project = db.projects.find_one({'_id': ObjectId(project_id)})
        if not project:
            return jsonify({"error": "Project not found"}), 404
        
        # Check if mentor exists
        mentor = db.users.find_one({'_id': ObjectId(mentor_id), 'role': 'Mentor'})
        if not mentor:
            return jsonify({"error": "Mentor not found"}), 404
        
        # Update project with mentor assignment
        result = db.projects.update_one(
            {'_id': ObjectId(project_id)},
            {
                '$set': {
                    'mentor_id': ObjectId(mentor_id),
                    'status': 'In Progress',
                    'assigned_at': datetime.now(UTC)
                }
            }
        )
        
        if result.modified_count == 1:
            # Log the activity
            log_activity(
                session['user_id'],
                'Mentor Assignment',
                f'Assigned mentor {mentor.get("username")} to project {project.get("title")}',
                project_id=project_id
            )
            
            return jsonify({
                "success": True,
                "message": f"Mentor {mentor.get('username')} assigned successfully to project {project.get('title')}"
            })
        else:
            return jsonify({"error": "Failed to assign mentor"}), 500
            
    except Exception as e:
        app.logger.error(f"Error assigning mentor: {e}")
 
 
        return jsonify({"error": "Internal server error"}), 500


@app.route('/api/mentee/goals', methods=['GET', 'POST'])
@login_required
@role_required('Mentee')
def mentee_goals():
    """Manage mentee learning goals"""
    if request.method == 'GET':
        try:
            goals = list(db.mentee_goals.find({'mentee_id': ObjectId(session['user_id'])}))
            for goal in goals:
                goal['_id'] = str(goal['_id'])
            return jsonify(goals)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            new_goal = {
                'mentee_id': ObjectId(session['user_id']),
                'title': data.get('title'),
                'description': data.get('description'),
                'status': 'pending',
                'created_at': datetime.now(UTC),
                'updated_at': datetime.now(UTC)
            }
            result = db.mentee_goals.insert_one(new_goal)
            return jsonify({"message": "Goal added successfully", "goal_id": str(result.inserted_id)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/api/mentee/goals/<goal_id>', methods=['PUT', 'DELETE'])
@login_required
@role_required('Mentee')
def mentee_goal(goal_id):
    """Update or delete a specific goal"""
    try:
        if request.method == 'PUT':
            data = request.get_json()
            db.mentee_goals.update_one(
                {'_id': ObjectId(goal_id), 'mentee_id': ObjectId(session['user_id'])},
                {'$set': {'status': data.get('status'), 'updated_at': datetime.now(UTC)}}
            )
            return jsonify({"message": "Goal updated successfully"})
        
        elif request.method == 'DELETE':
            db.mentee_goals.delete_one({'_id': ObjectId(goal_id), 'mentee_id': ObjectId(session['user_id'])})
            return jsonify({"message": "Goal deleted successfully"})
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/mentee/project_history')
@login_required
@role_required('Mentee')
def get_mentee_project_history():
    """Get all projects for a mentee"""
    try:
        mentee_id = session['user_id']
        projects = list(db.projects.find({'mentee_id': ObjectId(mentee_id)}).sort('created_at', -1))
        
        project_history = []
        for project in projects:
            # Count tasks
            task_count = len(project.get('tasks', []))
            
            project_history.append({
                '_id': str(project['_id']),
                'title': project.get('title', 'Untitled Project'),
                'description': project.get('description', ''),
                'status': project.get('status', 'Proposed'),
                'created_at': project.get('created_at', datetime.now(UTC)).isoformat(),
                'task_count': task_count
            })
        
        return jsonify(project_history)
        
    except Exception as e:
        app.logger.error(f"Error fetching mentee project history: {e}")
        return jsonify({"error": "Failed to load project history"}), 500
#
# In your app.py file, find the route @app.route('/api/mentee/feedback', methods=['POST'])
# and replace the entire function with this one.
#

@app.route('/api/mentee/feedback', methods=['POST'])
@login_required
@role_required('Mentee')
def submit_mentee_feedback():
    """
    Handles submission of detailed mentee feedback from the modal.
    Accepts feedback type, rating, subject, message, and priority.
    """
    try:
        data = request.get_json()

        # 1. --- Extract and Validate Required Data ---
        project_id = data.get('project_id')
        feedback_type = data.get('feedback_type')
        message = data.get('message')

        if not all([project_id, feedback_type, message]):
            return jsonify({"error": "Project ID, feedback type, and message are required fields."}), 400

        # 2. --- Construct the Feedback Document ---
        feedback_document = {
            'project_id': ObjectId(project_id),
            'mentee_id': ObjectId(session['user_id']),
            'feedback_type': feedback_type,
            'subject': data.get('subject'),  # This is optional
            'message': message.strip(),
            'priority': data.get('priority', 'low'),
            'submitted_at': datetime.now(UTC)
        }

        # Handle the optional rating field, ensuring it's an integer
        rating = data.get('rating')
        if rating:
            try:
                feedback_document['rating'] = int(rating)
            except (ValueError, TypeError):
                # If rating is not a valid number, ignore it or set to null
                feedback_document['rating'] = None

        # 3. --- Save Feedback to the Database ---
        # Insert into a dedicated collection for easier querying of all feedback
        db.mentee_feedback.insert_one(feedback_document.copy())

        # Also, embed the feedback within the corresponding project document
        result = db.projects.update_one(
            {'_id': ObjectId(project_id)},
            {'$push': {'mentee_feedback': feedback_document}}
        )

        if result.matched_count == 0:
            return jsonify({"error": "The specified project could not be found."}), 404

        # 4. --- Log the Activity and Return Success Response ---
        log_activity(
            user_id=session['user_id'],
            action_type='Feedback Submission',
            description=f'Mentee submitted "{feedback_type}" feedback for project.',
            project_id=project_id
        )

        return jsonify({"message": "Feedback submitted successfully!"})

    except Exception as e:
        app.logger.error(f"Error submitting mentee feedback: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500
@app.route('/add-task-comment', methods=['POST'])
@login_required
def add_task_comment():
    try:
        task_id = request.form.get('task_id')
        comment = request.form.get('comment')
        comment_type = request.form.get('comment_type', 'general')
        
        if not task_id or not comment:
            return jsonify({'success': False, 'message': 'Task ID and comment are required'})
        
        # Create new comment
        task_comment = TaskComment(
            task_id=task_id,
            user_id=current_user.id,
            comment=comment.strip(),
            comment_type=comment_type,
            created_at=datetime.utcnow()
        )
        
        db.session.add(task_comment)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Comment added successfully!',
            'comment_id': task_comment.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error adding comment: {str(e)}'})

@app.route('/get-task-comments')
@login_required
def get_task_comments():
   try:
        task_id = request.args.get('task_id')
        
        if not task_id:
            return jsonify({'success': False, 'message': 'Task ID is required'})
        
        # Get comments with author information
        comments = TaskComment.query.filter_by(task_id=task_id)\
            .join(User, TaskComment.user_id == User.id)\
            .add_columns(User.username, User.email)\
            .order_by(TaskComment.created_at.asc())\
            .all()
        
        comments_data = []
        for comment, username, email in comments:
            comments_data.append({
                'id': comment.id,
                'comment': comment.comment,
                'comment_type': comment.comment_type,
                'author_name': username,
                'author_email': email,
                'created_at': comment.created_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'comments': comments_data
        })
        
   except Exception as e:
         return jsonify({'success': False, 'message': f'Error: {str(e)}'})
    

@app.route('/api/projects/<project_id>/feedback', methods=['POST'])
@login_required
@role_required('Mentor')
def submit_feedback(project_id):
    try:
        feedback_data = request.json
        rating = feedback_data.get('rating')
        comments = feedback_data.get('comments')

        if not rating or not comments:
            return jsonify({'message': 'Rating and comments are required.'}), 400

        feedback_entry = {
            'mentor_id': ObjectId(session['user_id']),
            'rating': int(rating),
            'comments': comments,
            'timestamp': datetime.now(UTC)
        }

        db.projects.update_one(
            {'_id': ObjectId(project_id)},
            {'$push': {'feedback': feedback_entry}}
        )

        log_activity(session['user_id'], 'Feedback Submitted', f'Mentor submitted feedback for project {project_id}.')
        return jsonify({'message': 'Feedback submitted successfully!'}), 201

    except Exception as e:
        app.logger.error(f"Error submitting feedback: {e}")
        return jsonify({'message': 'An error occurred while submitting feedback.'}), 500
@app.route('/project/<project_id>/details')
@login_required
@role_required(['Mentor', 'Administrator', 'Coordinator'])
def project_details(project_id):
    """Detailed project view for mentors"""
    try:
        project = db.projects.find_one({'_id': ObjectId(project_id)})
        if not project:
            abort(404)
        
        # Check if current user has access to this project
        user_id = ObjectId(session['user_id'])
        user_role = session.get('role')
        
        if user_role not in ['Administrator', 'Coordinator']:
            if user_role == 'Mentor' and project.get('mentor_id') != user_id:
                abort(403)
        
        # Get related users
        mentee = get_user_by_id(project.get('mentee_id'))
        mentor = get_user_by_id(project.get('mentor_id')) if project.get('mentor_id') else None
        
        # Get project activity history
        activity_history = list(db.activity_logs.find(
            {'project_id': ObjectId(project_id)}
        ).sort('timestamp', -1).limit(50))
        
        # Get project files
        project_files = list(db.project_files.find(
            {'project_id': ObjectId(project_id)}
        ).sort('uploaded_at', -1))
        
        # Calculate project statistics
        tasks = project.get('tasks', [])
        total_tasks = len(tasks)
        completed_tasks = len([t for t in tasks if t.get('completed', False)])
        completion_percentage = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        # Get feedback history
        feedback_history = project.get('feedback', [])
        
        return render_template('project_details.html',
                             project=project,
                             mentee=mentee,
                             mentor=mentor,
                             activity_history=activity_history,
                             project_files=project_files,
                             total_tasks=total_tasks,
                             completed_tasks=completed_tasks,
                             completion_percentage=completion_percentage,
                             feedback_history=feedback_history)
                             
    except Exception as e:
        app.logger.error(f"Error loading project details: {e}")
        abort(500)
        
@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    """Download project files"""
    try:
        file_doc = db.project_files.find_one({'_id': ObjectId(file_id)})
        if not file_doc:
            abort(404)
        
        # Check if user has access to this file's project
        project = db.projects.find_one({'_id': file_doc['project_id']})
        user_id = ObjectId(session['user_id'])
        user_role = session.get('role')
        
        if user_role not in ['Administrator', 'Coordinator']:
            if user_role == 'Mentor' and project.get('mentor_id') != user_id:
                abort(403)
            if user_role == 'Mentee' and project.get('mentee_id') != user_id:
                abort(403)
        
        return send_file(file_doc['filepath'], as_attachment=True)
        
    except Exception as e:
        app.logger.error(f"Error downloading file: {e}")
        abort(500)
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get('user_id')
    
    if request.method == 'POST':
        try:
            # Get form data
            bio = request.form.get('bio', '')
            contact_info = request.form.get('contact_info', '')
            skills_input = request.form.get('skills', '')
            linkedin = request.form.get('linkedin', '')
            github = request.form.get('github', '')
            
            # Process skills (convert comma-separated string to list)
            skills = [skill.strip() for skill in skills_input.split(',')] if skills_input else []
            
            # Update profile data
            profile_data = {
                'bio': bio,
                'contact_info': contact_info,
                'skills': skills,
                'linkedin': linkedin,
                'github': github
            }
            
            # Update the user document in MongoDB
            result = db.users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'profile': profile_data}}
            )
            
            if result.modified_count > 0:
                flash('Your profile has been updated successfully!', 'success')
            else:
                flash('No changes were made to your profile.', 'info')
                
            return redirect(url_for('profile'))
            
        except Exception as e:
            app.logger.error(f"Error updating profile: {e}")
            flash('An error occurred while updating your profile. Please try again.', 'error')
            return redirect(url_for('profile'))

    # GET request - display profile form
    try:
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('dashboard'))
        
        # Ensure profile field exists
        profile_data = user.get('profile', {})
        
        return render_template('profile.html', user=user, profile=profile_data)
        
    except Exception as e:
        app.logger.error(f"Error loading profile: {e}")
        flash('An error occurred while loading your profile.', 'error')
        return redirect(url_for('dashboard'))
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    return jsonify({'csrf_token': csrf.generate_csrf()})
@app.errorhandler(400)
def bad_request(e):
    return render_template('400.html'), 400

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    print(f"🚀 Admin Dashboard URL: http://127.0.0.1:5000{app.config['ADMIN_SECRET_ROUTE']}")
    print("✅ Database indexes initialized successfully")
    initialize_database_indexes()
    socketio.run(app, host='192.168.244.222', port='5000', debug=True)

