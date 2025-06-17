from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from flask import abort
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'asdfghkl;'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin123@localhost:5433/inventorydb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    role = db.Column(db.String(50), nullable=False, default='user')
    is_active = db.Column(db.Boolean, default=True)


class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    last_modified_by = db.Column(db.String(150))
    last_modified_date = db.Column(db.DateTime)
    user = db.relationship('User', backref='items')  # Adds relationship to fetch username easily




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        email = request.form['email']
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully. Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            if not user.is_active:
                error = 'Your account is disabled. Contact admin.'
            else:
                login_user(user)
                return redirect(url_for('dashboard'))
        else:
            error = 'Incorrect Password'

    return render_template('login.html', error=error)


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users = User.query.all()
        inventory = InventoryItem.query.all()
        return render_template('admin_dashboard.html', users=users, inventory=inventory)
    else:
        inventory = InventoryItem.query.filter_by(user_id=current_user.id).all()
        return render_template('user_dashboard.html', inventory=inventory)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/add_item', methods=['POST'])
@login_required
def add_item():
    name = request.form['name']
    quantity = request.form['quantity']
    new_item = InventoryItem(
        name=name,
        quantity=quantity,
        user_id=current_user.id,
        last_modified_by=current_user.username  # Optional
    )
    db.session.add(new_item)
    db.session.commit()
    return redirect(url_for('dashboard'))



@app.route('/update_item/<int:item_id>', methods=['POST'])
@login_required
def update_item(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    if current_user.role != 'admin':
        abort(403)
    item.name = request.form['name']
    item.quantity = int(request.form['quantity'])
    item.last_modified_by = current_user.username
    item.last_modified_date = datetime.utcnow()
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('dashboard'))

    item = InventoryItem.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash(f"Item '{item.name}' deleted.")
    return redirect(url_for('dashboard'))



@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        flash("You can't delete yourself.")
        return redirect(url_for('dashboard'))

    # Delete user and their inventory
    InventoryItem.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} and their items were deleted.')
    return redirect(url_for('dashboard'))

@app.route('/disable_user/<int:user_id>', methods=['POST'])
@login_required
def disable_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You can't disable yourself.")
        return redirect(url_for('dashboard'))

    user.is_active = False
    db.session.commit()
    flash(f'User {user.username} has been disabled.')
    return redirect(url_for('dashboard'))

@app.route('/toggle_user/<int:user_id>', methods=['POST'])
@login_required
def toggle_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You can't change your own status.")
        return redirect(url_for('dashboard'))

    user.is_active = not user.is_active
    db.session.commit()
    status = 'enabled' if user.is_active else 'disabled'
    flash(f'User {user.username} has been {status}.')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Create admin user if not exists
        from sqlalchemy.exc import SQLAlchemyError
        try:
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                hashed_password = "admin123"
                admin_user = User(username='admin', password=hashed_password, role='admin')
                db.session.add(admin_user)
                db.session.commit()
                print("Admin user created.")
            else:
                print("Admin user already exists.")
        except SQLAlchemyError as e:
            print("Error initializing admin:", e)

    app.run(debug=True, port=5000)

