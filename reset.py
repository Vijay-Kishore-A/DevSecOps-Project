from app import app, db, User  # import app, db, and models directly from app.py
from sqlalchemy.exc import SQLAlchemyError

with app.app_context():
    print("Dropping all tables...")
    db.drop_all()

    print("Creating all tables...")
    db.create_all()

    # Optionally create a default admin user
    try:
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            from app import bcrypt
            hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin_user = User(username='admin', password=hashed_password, role='admin')
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created.")
        else:
            print("Admin user already exists.")
    except SQLAlchemyError as e:
        print("Error initializing admin:", e)
