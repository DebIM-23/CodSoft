# contact_book.py
from flask import Flask, render_template_string, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from io import BytesIO
from base64 import b64encode

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contact_book.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Generate a simple CB logo
def generate_logo():
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new('RGB', (100, 100), color=(52, 152, 219))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 40)
    except:
        font = ImageFont.load_default()
    draw.text((30, 30), "CB", fill=(255, 255, 255), font=font)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return b64encode(buffered.getvalue()).decode('utf-8')

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    contacts = db.relationship('Contact', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100))
    address = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    logo = generate_logo()
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Contact Book - Home</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
                header { background: #3498db; color: white; padding: 1rem; display: flex; justify-content: space-between; }
                .logo { height: 40px; width: 40px; border-radius: 50%; background: white; color: #3498db; 
                        display: flex; align-items: center; justify-content: center; font-weight: bold; }
                nav a { color: white; text-decoration: none; margin-left: 1rem; }
                main { padding: 2rem; text-align: center; }
                .hero { max-width: 800px; margin: 0 auto; }
                .btn { display: inline-block; padding: 0.75rem 1.5rem; background: #3498db; 
                       color: white; text-decoration: none; border-radius: 5px; margin: 0.5rem; }
            </style>
        </head>
        <body>
            <header>
                <div style="display: flex; align-items: center;">
                    <img src="data:image/png;base64,{{ logo }}" alt="CB Logo" style="height: 40px; margin-right: 1rem;">
                    <h1>Contact Book</h1>
                </div>
                <nav>
                    {% if current_user.is_authenticated %}
                        <a href="{{ url_for('contacts') }}">Contacts</a>
                        <a href="{{ url_for('logout') }}">Logout</a>
                    {% else %}
                        <a href="{{ url_for('login') }}">Login</a>
                        <a href="{{ url_for('register') }}">Register</a>
                    {% endif %}
                </nav>
            </header>
            <main>
                <div class="hero">
                    <h2>Welcome to Contact Book</h2>
                    <p>Manage your contacts easily and efficiently</p>
                    {% if not current_user.is_authenticated %}
                        <div>
                            <a href="{{ url_for('login') }}" class="btn">Login</a>
                            <a href="{{ url_for('register') }}" class="btn">Register</a>
                        </div>
                    {% endif %}
                </div>
            </main>
        </body>
        </html>
    ''', logo=logo)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('contacts'))
        
        flash('Invalid username or password')
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Contact Book - Login</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
                header { background: #3498db; color: white; padding: 1rem; }
                .form-container { max-width: 400px; margin: 2rem auto; padding: 2rem; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .form-group { margin-bottom: 1rem; }
                label { display: block; margin-bottom: 0.5rem; }
                input { width: 100%; padding: 0.5rem; box-sizing: border-box; }
                .btn { background: #3498db; color: white; border: none; padding: 0.75rem; width: 100%; cursor: pointer; }
                .flash { background: #e74c3c; color: white; padding: 0.5rem; margin-bottom: 1rem; }
            </style>
        </head>
        <body>
            <header>
                <h1>Contact Book - Login</h1>
            </header>
            <div class="form-container">
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        <div class="flash">{{ messages[0] }}</div>
                    {% endif %}
                {% endwith %}
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn">Login</button>
                </form>
                <p style="margin-top: 1rem;">Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
            </div>
        </body>
        </html>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Contact Book - Register</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
                header { background: #3498db; color: white; padding: 1rem; }
                .form-container { max-width: 400px; margin: 2rem auto; padding: 2rem; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .form-group { margin-bottom: 1rem; }
                label { display: block; margin-bottom: 0.5rem; }
                input { width: 100%; padding: 0.5rem; box-sizing: border-box; }
                .btn { background: #3498db; color: white; border: none; padding: 0.75rem; width: 100%; cursor: pointer; }
                .flash { background: #e74c3c; color: white; padding: 0.5rem; margin-bottom: 1rem; }
            </style>
        </head>
        <body>
            <header>
                <h1>Contact Book - Register</h1>
            </header>
            <div class="form-container">
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        <div class="flash">{{ messages[0] }}</div>
                    {% endif %}
                {% endwith %}
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn">Register</button>
                </form>
                <p style="margin-top: 1rem;">Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
            </div>
        </body>
        </html>
    ''')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/contacts')
@login_required
def contacts():
    user_contacts = Contact.query.filter_by(user_id=current_user.id).all()
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Contact Book - Contacts</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
                header { background: #3498db; color: white; padding: 1rem; display: flex; justify-content: space-between; }
                nav a { color: white; text-decoration: none; margin-left: 1rem; }
                main { padding: 2rem; }
                table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
                th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }
                th { background: #3498db; color: white; }
                tr:hover { background: #f5f5f5; }
                .btn { padding: 0.5rem 1rem; color: white; text-decoration: none; border-radius: 4px; }
                .btn-add { background: #2ecc71; }
                .btn-edit { background: #f39c12; }
                .btn-delete { background: #e74c3c; }
                .header-container { display: flex; justify-content: space-between; align-items: center; }
                .flash { background: #2ecc71; color: white; padding: 0.5rem; margin-bottom: 1rem; }
            </style>
        </head>
        <body>
            <header>
                <div style="display: flex; align-items: center;">
                    <img src="data:image/png;base64,{{ logo }}" alt="CB Logo" style="height: 40px; margin-right: 1rem;">
                    <h1>Contact Book</h1>
                </div>
                <nav>
                    <a href="{{ url_for('contacts') }}">Contacts</a>
                    <a href="{{ url_for('add_contact') }}">Add Contact</a>
                    <a href="{{ url_for('search') }}">Search</a>
                    <a href="{{ url_for('logout') }}">Logout</a>
                </nav>
            </header>
            <main>
                <div class="header-container">
                    <h2>Your Contacts</h2>
                    <a href="{{ url_for('add_contact') }}" class="btn btn-add">Add New Contact</a>
                </div>
                
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        <div class="flash">{{ messages[0] }}</div>
                    {% endif %}
                {% endwith %}
                
                {% if contacts %}
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Phone</th>
                                <th>Email</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for contact in contacts %}
                                <tr>
                                    <td>{{ contact.name }}</td>
                                    <td>{{ contact.phone }}</td>
                                    <td>{{ contact.email if contact.email else '-' }}</td>
                                    <td>
                                        <a href="{{ url_for('edit_contact', contact_id=contact.id) }}" class="btn btn-edit">Edit</a>
                                        <a href="{{ url_for('delete_contact', contact_id=contact.id) }}" class="btn btn-delete" onclick="return confirm('Are you sure?')">Delete</a>
                                    </td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p>You don't have any contacts yet. <a href="{{ url_for('add_contact') }}">Add your first contact</a></p>
                {% endif %}
            </main>
        </body>
        </html>
    ''', contacts=user_contacts, logo=generate_logo())

@app.route('/add_contact', methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        email = request.form.get('email', '')
        address = request.form.get('address', '')
        
        contact = Contact(
            name=name,
            phone=phone,
            email=email,
            address=address,
            user_id=current_user.id
        )
        
        db.session.add(contact)
        db.session.commit()
        
        flash('Contact added successfully!')
        return redirect(url_for('contacts'))
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Contact Book - Add Contact</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
                header { background: #3498db; color: white; padding: 1rem; }
                .form-container { max-width: 600px; margin: 2rem auto; padding: 2rem; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .form-group { margin-bottom: 1rem; }
                label { display: block; margin-bottom: 0.5rem; }
                input, textarea { width: 100%; padding: 0.5rem; box-sizing: border-box; }
                textarea { min-height: 100px; }
                .btn { background: #3498db; color: white; border: none; padding: 0.75rem; cursor: pointer; margin-right: 0.5rem; }
                .btn-cancel { background: #95a5a6; }
            </style>
        </head>
        <body>
            <header>
                <div style="display: flex; align-items: center;">
                    <img src="data:image/png;base64,{{ logo }}" alt="CB Logo" style="height: 40px; margin-right: 1rem;">
                    <h1>Contact Book - Add Contact</h1>
                </div>
            </header>
            <div class="form-container">
                <form method="POST">
                    <div class="form-group">
                        <label for="name">Name*</label>
                        <input type="text" id="name" name="name" required>
                    </div>
                    <div class="form-group">
                        <label for="phone">Phone*</label>
                        <input type="text" id="phone" name="phone" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email">
                    </div>
                    <div class="form-group">
                        <label for="address">Address</label>
                        <textarea id="address" name="address"></textarea>
                    </div>
                    <button type="submit" class="btn">Save Contact</button>
                    <a href="{{ url_for('contacts') }}" class="btn btn-cancel">Cancel</a>
                </form>
            </div>
        </body>
        </html>
    ''', logo=generate_logo())

@app.route('/edit_contact/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def edit_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    if contact.user_id != current_user.id:
        flash('You cannot edit this contact')
        return redirect(url_for('contacts'))
    
    if request.method == 'POST':
        contact.name = request.form['name']
        contact.phone = request.form['phone']
        contact.email = request.form.get('email', '')
        contact.address = request.form.get('address', '')
        
        db.session.commit()
        flash('Contact updated successfully!')
        return redirect(url_for('contacts'))
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Contact Book - Edit Contact</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
                header { background: #3498db; color: white; padding: 1rem; }
                .form-container { max-width: 600px; margin: 2rem auto; padding: 2rem; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .form-group { margin-bottom: 1rem; }
                label { display: block; margin-bottom: 0.5rem; }
                input, textarea { width: 100%; padding: 0.5rem; box-sizing: border-box; }
                textarea { min-height: 100px; }
                .btn { background: #3498db; color: white; border: none; padding: 0.75rem; cursor: pointer; margin-right: 0.5rem; }
                .btn-cancel { background: #95a5a6; }
            </style>
        </head>
        <body>
            <header>
                <div style="display: flex; align-items: center;">
                    <img src="data:image/png;base64,{{ logo }}" alt="CB Logo" style="height: 40px; margin-right: 1rem;">
                    <h1>Contact Book - Edit Contact</h1>
                </div>
            </header>
            <div class="form-container">
                <form method="POST">
                    <div class="form-group">
                        <label for="name">Name*</label>
                        <input type="text" id="name" name="name" value="{{ contact.name }}" required>
                    </div>
                    <div class="form-group">
                        <label for="phone">Phone*</label>
                        <input type="text" id="phone" name="phone" value="{{ contact.phone }}" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email" value="{{ contact.email if contact.email else '' }}">
                    </div>
                    <div class="form-group">
                        <label for="address">Address</label>
                        <textarea id="address" name="address">{{ contact.address if contact.address else '' }}</textarea>
                    </div>
                    <button type="submit" class="btn">Update Contact</button>
                    <a href="{{ url_for('contacts') }}" class="btn btn-cancel">Cancel</a>
                </form>
            </div>
        </body>
        </html>
    ''', contact=contact, logo=generate_logo())

@app.route('/delete_contact/<int:contact_id>')
@login_required
def delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    if contact.user_id != current_user.id:
        flash('You cannot delete this contact')
        return redirect(url_for('contacts'))
    
    db.session.delete(contact)
    db.session.commit()
    
    flash('Contact deleted successfully!')
    return redirect(url_for('contacts'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    search_term = None
    results = []
    
    if request.method == 'POST':
        search_term = request.form['search_term']
        results = Contact.query.filter(
            (Contact.name.contains(search_term)) | 
            (Contact.phone.contains(search_term)),
            Contact.user_id == current_user.id
        ).all()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Contact Book - Search</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
                header { background: #3498db; color: white; padding: 1rem; }
                .search-container { max-width: 800px; margin: 2rem auto; }
                .search-form { display: flex; gap: 1rem; margin-bottom: 2rem; }
                .search-form input { flex: 1; padding: 0.75rem; }
                .search-form button { padding: 0.75rem 1.5rem; background: #3498db; color: white; border: none; cursor: pointer; }
                table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
                th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }
                th { background: #3498db; color: white; }
                .btn { padding: 0.5rem 1rem; color: white; text-decoration: none; border-radius: 4px; }
                .btn-edit { background: #f39c12; }
                .btn-delete { background: #e74c3c; }
                .no-results { text-align: center; padding: 2rem; }
            </style>
        </head>
        <body>
            <header>
                <div style="display: flex; align-items: center;">
                    <img src="data:image/png;base64,{{ logo }}" alt="CB Logo" style="height: 40px; margin-right: 1rem;">
                    <h1>Contact Book - Search</h1>
                </div>
            </header>
            <div class="search-container">
                <form method="POST" class="search-form">
                    <input type="text" name="search_term" placeholder="Search by name or phone..." value="{{ search_term if search_term else '' }}" required>
                    <button type="submit">Search</button>
                </form>
                
                {% if search_term %}
                    <h2>Search Results for "{{ search_term }}"</h2>
                    {% if results %}
                        <table>
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Phone</th>
                                    <th>Email</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for contact in results %}
                                    <tr>
                                        <td>{{ contact.name }}</td>
                                        <td>{{ contact.phone }}</td>
                                        <td>{{ contact.email if contact.email else '-' }}</td>
                                        <td>
                                            <a href="{{ url_for('edit_contact', contact_id=contact.id) }}" class="btn btn-edit">Edit</a>
                                            <a href="{{ url_for('delete_contact', contact_id=contact.id) }}" class="btn btn-delete" onclick="return confirm('Are you sure?')">Delete</a>
                                        </td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% else %}
                        <p class="no-results">No contacts found matching your search.</p>
                    {% endif %}
                {% endif %}
            </div>
        </body>
        </html>
    ''', search_term=search_term, contacts=results, logo=generate_logo())

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)