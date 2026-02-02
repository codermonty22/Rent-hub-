from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from dotenv import load_dotenv
import jwt
import datetime
from functools import wraps
import re
import secrets
import os
import string
import requests
import pyotp
import qrcode
import io
import base64
import logging

from utils.security import validate_strong_password, record_failed_login_user, record_failed_login_ip, is_user_locked_out, is_ip_locked_out, reset_failed_logins

load_dotenv()

app = Flask(__name__)
CORS(app)

# Rate limiting setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per day", "100 per hour"]
)

def sanitize_filename(filename):
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    sanitized = ''.join(c if c in valid_chars else '_' for c in filename)
    return sanitized

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL')
app.config['ADMIN_PASSWORD'] = os.environ.get('ADMIN_PASSWORD')


# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client.renthub
users_collection = db.users
products_collection = db.products
reviews_collection = db.reviews
chats_collection = db.chats

# JWT token verification decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_collection.find_one({'email': data['email']})
            if not current_user:
                return jsonify({'message': 'Token is invalid'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# Validation functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    # Basic phone validation - you can make this more sophisticated
    pattern = r'^\+?[\d\s\-\(\)]{8,}$'
    return re.match(pattern, phone) is not None

def validate_password(password):
    # Enhanced password policy: minimum 12 chars, uppercase, lowercase, digit, special char
    return validate_strong_password(password)



def generate_2fa_secret():
    """Generate a new TOTP secret"""
    return pyotp.random_base32()

def generate_qr_code(secret, email):
    """Generate QR code for 2FA setup"""
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="RentHub")

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    # Convert to base64 for frontend
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{qr_code_base64}"

def verify_2fa_code(secret, code):
    """Verify TOTP code"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

# Routes
@app.route('/api/signup', methods=['POST'])
@limiter.limit("5 per minute")
def signup():
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['firstName', 'lastName', 'email', 'phone', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'{field} is required'}), 400

        # Validate email format
        if not validate_email(data['email']):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400

        # Validate phone format
        if not validate_phone(data['phone']):
            return jsonify({'success': False, 'message': 'Invalid phone number format'}), 400

        # Validate password strength
        if not validate_password(data['password']):
            return jsonify({
                'success': False,
                'message': 'Password must be at least 12 characters long and contain uppercase, lowercase, number, and special character'
            }), 400

        # Check if user already exists
        if users_collection.find_one({'email': data['email']}):
            return jsonify({'success': False, 'message': 'User already exists with this email'}), 409

        # Check if phone number already exists
        if users_collection.find_one({'phone': data['phone']}):
            return jsonify({'success': False, 'message': 'User already exists with this phone number'}), 409

        # Hash password
        hashed_password = generate_password_hash(data['password'])

        # Create user document
        user_data = {
            'firstName': data['firstName'].strip(),
            'lastName': data['lastName'].strip(),
            'email': data['email'].lower().strip(),
            'phone': data['phone'].strip(),
            'password': hashed_password,
            'address': '',
            'bio': '',
            'profilePicture': '',
            'isActive': True,
            'isVerified': False,
            'twoFactorEnabled': False,
            'createdAt': datetime.datetime.utcnow(),
            'updatedAt': datetime.datetime.utcnow(),
            'lastLoginAt': None,
            'loginHistory': [],
            'itemsRented': 0,
            'itemsListed': 0,
            'rating': 0.0,
            'totalRatings': 0
        }

        # Insert user into database
        result = users_collection.insert_one(user_data)

        if result.inserted_id:
            return jsonify({
                'success': True,
                'message': 'User registered successfully',
                'userId': str(result.inserted_id)
            }), 201
        else:
            return jsonify({'success': False, 'message': 'Failed to create user'}), 500

    except Exception as e:
        print(f"Signup error: {str(e)}")
        # Check if it's a JSON parsing error
        if "Expecting value" in str(e) or "JSON" in str(e):
            return jsonify({'success': False, 'message': 'Invalid JSON format'}), 400
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    try:
        data = request.get_json()
        ip = request.remote_addr

        if not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Email and password are required'}), 400

        email = data['email'].lower().strip()

        # Check if IP or user is locked out
        if is_ip_locked_out(ip):
            return jsonify({'message': 'Too many failed login attempts from this IP. Try again later.'}), 429
        if is_user_locked_out(email):
            return jsonify({'message': 'Account temporarily locked due to multiple failed login attempts. Try again later.'}), 429

        # Find user by email
        user = users_collection.find_one({'email': email})

        if not user:
            record_failed_login_user(email)
            record_failed_login_ip(ip)
            return jsonify({'message': 'Invalid email or password'}), 401

        # Check if account is active
        if not user.get('isActive', True):
            return jsonify({'message': 'Account is deactivated'}), 401

        # Verify password
        if not check_password_hash(user['password'], data['password']):
            record_failed_login_user(email)
            record_failed_login_ip(ip)
            return jsonify({'message': 'Invalid email or password'}), 401

        # Check if 2FA is enabled
        if user.get('twoFactorEnabled', False):
            twofa_code = data.get('twofaCode')
            if not twofa_code:
                return jsonify({
                    'message': 'Two-factor authentication code is required',
                    'requires2FA': True
                }), 200  # 200 to indicate partial success

            secret = user.get('twoFactorSecret')
            if not secret or not verify_2fa_code(secret, twofa_code):
                record_failed_login_user(email)
                record_failed_login_ip(ip)
                return jsonify({'message': 'Invalid two-factor authentication code'}), 401

        # Reset failed login attempts on successful login
        reset_failed_logins(email, ip)

        # Update login history
        login_info = {
            'timestamp': datetime.datetime.utcnow(),
            'ip': ip,
            'userAgent': request.headers.get('User-Agent', 'Unknown')
        }

        users_collection.update_one(
            {'_id': user['_id']},
            {
                '$set': {
                    'lastLoginAt': datetime.datetime.utcnow(),
                    'updatedAt': datetime.datetime.utcnow()
                },
                '$push': {
                    'loginHistory': {
                        '$each': [login_info],
                        '$slice': -10  # Keep only last 10 login records
                    }
                }
            }
        )

        # Generate JWT token
        token_payload = {
            'email': user['email'],
            'userId': str(user['_id']),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }

        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')

        # Return user data (excluding sensitive information)
        user_data = {
            'id': str(user['_id']),
            'firstName': user['firstName'],
            'lastName': user['lastName'],
            'email': user['email'],
            'phone': user['phone'],
            'address': user.get('address', ''),
            'bio': user.get('bio', ''),
            'profilePicture': user.get('profilePicture', ''),
            'isVerified': user.get('isVerified', False),
            'twoFactorEnabled': user.get('twoFactorEnabled', False),
            'itemsRented': user.get('itemsRented', 0),
            'itemsListed': user.get('itemsListed', 0),
            'rating': user.get('rating', 0.0)
        }

        return jsonify({
            'token': token,
            'user': user_data,
            'message': 'Login successful'
        }), 200

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    try:
        user_data = {
            'id': str(current_user['_id']),
            'firstName': current_user['firstName'],
            'lastName': current_user['lastName'],
            'email': current_user['email'],
            'phone': current_user['phone'],
            'address': current_user.get('address', ''),
            'bio': current_user.get('bio', ''),
            'profilePicture': current_user.get('profilePicture', ''),
            'isVerified': current_user.get('isVerified', False),
            'twoFactorEnabled': current_user.get('twoFactorEnabled', False),
            'itemsRented': current_user.get('itemsRented', 0),
            'itemsListed': current_user.get('itemsListed', 0),
            'rating': current_user.get('rating', 0.0),
            'createdAt': current_user.get('createdAt'),
            'lastLoginAt': current_user.get('lastLoginAt')
        }

        return jsonify({
            'success': True,
            'user': user_data
        }), 200

    except Exception as e:
        print(f"Get profile error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    try:
        data = request.get_json()

        # Fields that can be updated
        updatable_fields = ['firstName', 'lastName', 'phone', 'address', 'bio']
        update_data = {}

        for field in updatable_fields:
            if field in data:
                if field in ['firstName', 'lastName'] and data[field]:
                    update_data[field] = data[field].strip()
                elif field == 'phone' and data[field]:
                    if validate_phone(data[field]):
                        # Check if phone number is already used by another user
                        existing_user = users_collection.find_one({
                            'phone': data[field].strip(),
                            '_id': {'$ne': current_user['_id']}
                        })
                        if existing_user:
                            return jsonify({
                                'success': False,
                                'message': 'Phone number is already in use'
                            }), 409
                        update_data[field] = data[field].strip()
                    else:
                        return jsonify({
                            'success': False,
                            'message': 'Invalid phone number format'
                        }), 400
                else:
                    update_data[field] = data[field]

        # Always update the updatedAt timestamp
        update_data['updatedAt'] = datetime.datetime.utcnow()

        # Update user in database
        result = users_collection.update_one(
            {'_id': current_user['_id']},
            {'$set': update_data}
        )

        if result.modified_count > 0 or result.matched_count > 0:
            # Get updated user data
            updated_user = users_collection.find_one({'_id': current_user['_id']})
            user_data = {
                'id': str(updated_user['_id']),
                'firstName': updated_user['firstName'],
                'lastName': updated_user['lastName'],
                'email': updated_user['email'],
                'phone': updated_user['phone'],
                'address': updated_user.get('address', ''),
                'bio': updated_user.get('bio', ''),
                'profilePicture': updated_user.get('profilePicture', ''),
                'isVerified': updated_user.get('isVerified', False),
                'twoFactorEnabled': updated_user.get('twoFactorEnabled', False),
                'itemsRented': updated_user.get('itemsRented', 0),
                'itemsListed': updated_user.get('itemsListed', 0),
                'rating': updated_user.get('rating', 0.0)
            }

            return jsonify({
                'success': True,
                'message': 'Profile updated successfully',
                'user': user_data
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'No changes made to profile'
            }), 400

    except Exception as e:
        print(f"Update profile error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/change-password', methods=['POST'])
@token_required
def change_password(current_user):
    try:
        data = request.get_json()

        if not data.get('currentPassword') or not data.get('newPassword'):
            return jsonify({
                'success': False,
                'message': 'Current password and new password are required'
            }), 400

        # Verify current password
        if not check_password_hash(current_user['password'], data['currentPassword']):
            return jsonify({
                'success': False,
                'message': 'Current password is incorrect'
            }), 401

        # Validate new password
        if not validate_password(data['newPassword']):
            return jsonify({
                'success': False,
                'message': 'New password must be at least 12 characters long and contain uppercase, lowercase, number, and special character'
            }), 400

        # Check if new password is different from current password
        if check_password_hash(current_user['password'], data['newPassword']):
            return jsonify({
                'success': False,
                'message': 'New password must be different from current password'
            }), 400

        # Hash new password
        new_hashed_password = generate_password_hash(data['newPassword'])

        # Update password in database
        result = users_collection.update_one(
            {'_id': current_user['_id']},
            {
                '$set': {
                    'password': new_hashed_password,
                    'updatedAt': datetime.datetime.utcnow()
                }
            }
        )

        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Password changed successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to change password'
            }), 500

    except Exception as e:
        print(f"Change password error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/setup-2fa', methods=['POST'])
@token_required
def setup_two_factor(current_user):
    try:
        # Generate new TOTP secret
        secret = generate_2fa_secret()

        # Generate QR code
        qr_code = generate_qr_code(secret, current_user['email'])

        # Store secret temporarily (will be confirmed later)
        users_collection.update_one(
            {'_id': current_user['_id']},
            {
                '$set': {
                    'temp2faSecret': secret,
                    'updatedAt': datetime.datetime.utcnow()
                }
            }
        )

        return jsonify({
            'success': True,
            'qrCode': qr_code,
            'secret': secret  # For manual entry
        }), 200

    except Exception as e:
        print(f"Setup 2FA error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/verify-2fa-setup', methods=['POST'])
@token_required
def verify_two_factor_setup(current_user):
    try:
        data = request.get_json()
        code = data.get('code')

        if not code:
            return jsonify({'success': False, 'message': 'Verification code is required'}), 400

        temp_secret = current_user.get('temp2faSecret')
        if not temp_secret:
            return jsonify({'success': False, 'message': '2FA setup not initiated'}), 400

        if not verify_2fa_code(temp_secret, code):
            return jsonify({'success': False, 'message': 'Invalid verification code'}), 400

        # Enable 2FA and store secret
        users_collection.update_one(
            {'_id': current_user['_id']},
            {
                '$set': {
                    'twoFactorEnabled': True,
                    'twoFactorSecret': temp_secret,
                    'updatedAt': datetime.datetime.utcnow()
                },
                '$unset': {
                    'temp2faSecret': 1
                }
            }
        )

        return jsonify({
            'success': True,
            'message': 'Two-factor authentication enabled successfully'
        }), 200

    except Exception as e:
        print(f"Verify 2FA setup error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/toggle-2fa', methods=['POST'])
@token_required
def toggle_two_factor(current_user):
    try:
        current_status = current_user.get('twoFactorEnabled', False)

        if current_status:
            # Disable 2FA
            users_collection.update_one(
                {'_id': current_user['_id']},
                {
                    '$set': {
                        'twoFactorEnabled': False,
                        'updatedAt': datetime.datetime.utcnow()
                    },
                    '$unset': {
                        'twoFactorSecret': 1
                    }
                }
            )
            return jsonify({
                'success': True,
                'message': 'Two-factor authentication disabled',
                'twoFactorEnabled': False
            }), 200
        else:
            # Enable 2FA - redirect to setup
            return jsonify({
                'success': False,
                'message': 'Please use /api/setup-2fa to enable 2FA',
                'requiresSetup': True
            }), 400

    except Exception as e:
        print(f"Toggle 2FA error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/login-history', methods=['GET'])
@token_required
def get_login_history(current_user):
    try:
        login_history = current_user.get('loginHistory', [])

        # Format login history for display
        formatted_history = []
        for login in login_history:
            formatted_history.append({
                'timestamp': login.get('timestamp'),
                'ip': login.get('ip', 'Unknown'),
                'userAgent': login.get('userAgent', 'Unknown')
            })

        return jsonify({
            'success': True,
            'loginHistory': formatted_history
        }), 200

    except Exception as e:
        print(f"Get login history error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/deactivate-account', methods=['POST'])
@token_required
def deactivate_account(current_user):
    try:
        data = request.get_json()

        if not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Password is required to deactivate account'
            }), 400

        # Verify password
        if not check_password_hash(current_user['password'], data['password']):
            return jsonify({
                'success': False,
                'message': 'Incorrect password'
            }), 401

        # Deactivate account
        result = users_collection.update_one(
            {'_id': current_user['_id']},
            {
                '$set': {
                    'isActive': False,
                    'updatedAt': datetime.datetime.utcnow()
                }
            }
        )

        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Account deactivated successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to deactivate account'
            }), 500

    except Exception as e:
        print(f"Deactivate account error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Test database connection
        db.command('ping')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.datetime.utcnow()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow()
        }), 500

# New API endpoint to create a product listing
@app.route('/api/products', methods=['POST'])
@token_required
def create_product(current_user):
    try:
        # Check if request has form data
        if not request.form:
            return jsonify({'success': False, 'message': 'No form data provided'}), 400

        # Required fields
        required_fields = ['title', 'description', 'category', 'price', 'condition', 'rental_type', 'owner_email', 'owner_phone', 'owner_address', 'location']
        for field in required_fields:
            if not request.form.get(field):
                return jsonify({'success': False, 'message': f'{field} is required'}), 400

        # Validate email and phone
        if not validate_email(request.form['owner_email']):
            return jsonify({'success': False, 'message': 'Invalid owner email format'}), 400
        if not validate_phone(request.form['owner_phone']):
            return jsonify({'success': False, 'message': 'Invalid owner phone format'}), 400

        # Validate price is a number
        try:
            price = float(request.form['price'])
            if price < 0:
                return jsonify({'success': False, 'message': 'Price must be non-negative'}), 400
        except ValueError:
            return jsonify({'success': False, 'message': 'Price must be a number'}), 400

        # Check images and cert files
        images = request.files.getlist('images')
        cert = request.files.get('cert')

        if not images or len(images) < 5:
            return jsonify({'success': False, 'message': 'At least 5 product images are required'}), 400
        if not cert:
            return jsonify({'success': False, 'message': 'Product certification file is required'}), 400

        # Save images
        image_paths = []
        images_dir = os.path.join(os.path.dirname(__file__), 'uploads', 'images')
        os.makedirs(images_dir, exist_ok=True)
        for img in images:
            original_filename = img.filename
            sanitized_filename = sanitize_filename(original_filename)
            filename = secrets.token_hex(8) + '_' + sanitized_filename
            filepath = os.path.join(images_dir, filename)
            img.save(filepath)
            image_paths.append('/uploads/images/' + filename)

        # Save cert
        certs_dir = os.path.join(os.path.dirname(__file__), 'uploads', 'certs')
        os.makedirs(certs_dir, exist_ok=True)
        original_cert_filename = cert.filename
        sanitized_cert_filename = sanitize_filename(original_cert_filename)
        cert_filename = secrets.token_hex(8) + '_' + sanitized_cert_filename
        cert_filepath = os.path.join(certs_dir, cert_filename)
        cert.save(cert_filepath)
        cert_path = '/uploads/certs/' + cert_filename

        # Create product document
        product_data = {
            'title': request.form['title'].strip(),
            'description': request.form['description'].strip(),
            'category': request.form['category'].strip(),
            'price': price,
            'condition': request.form['condition'].strip(),
            'rental_type': request.form['rental_type'].strip(),
            'owner_email': request.form['owner_email'].strip(),
            'owner_phone': request.form['owner_phone'].strip(),
            'owner_address': request.form['owner_address'].strip(),
            'location': request.form['location'].strip(),
            'images': image_paths,
            'cert': cert_path,
            'status': 'pending',  # Default status for new listings
            'created_at': datetime.datetime.utcnow(),
            'updated_at': datetime.datetime.utcnow(),
            'owner_id': current_user['_id']
        }

        # Insert into products collection
        result = products_collection.insert_one(product_data)

        if result.inserted_id:
            return jsonify({'success': True, 'message': 'Product listing created successfully', 'product_id': str(result.inserted_id)}), 201
        else:
            return jsonify({'success': False, 'message': 'Failed to create product listing'}), 500

    except Exception as e:
        print(f"Create product error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

# Frontend serving
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))

@app.route('/')
def serve_index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/auth')
def serve_auth():
    return send_from_directory(FRONTEND_DIR, 'auth.html')

@app.route('/<path:filename>')
def serve_static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)

import logging
import os

@app.route('/uploads/<path:filename>')
def serve_uploads(filename):
    uploads_dir = os.path.join(os.path.dirname(__file__), 'uploads')
    # Normalize path separators for Windows
    normalized_filename = filename.replace('/', os.sep).replace('\\', os.sep)
    full_path = os.path.join(uploads_dir, normalized_filename)
    if not os.path.isfile(full_path):
        logging.error(f"File not found: {full_path}")
        return jsonify({'message': 'File not found'}), 404
    logging.info(f"Serving file: {full_path}")
    return send_from_directory(uploads_dir, filename)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'message': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'message': 'Internal server error'}), 500

# New API endpoint to get a single product by ID
@app.route('/api/products/<product_id>', methods=['GET'])
def get_product(product_id):
    try:
        from bson import ObjectId
        product = products_collection.find_one({'_id': ObjectId(product_id)})
        if not product:
            return jsonify({'success': False, 'message': 'Product not found'}), 404

        # Convert ObjectId fields to string
        product['_id'] = str(product['_id'])
        if 'owner_id' in product:
            product['owner_id'] = str(product['owner_id'])
        if 'approved_by' in product and product['approved_by']:
            product['approved_by'] = str(product['approved_by'])
        if 'rejected_by' in product and product['rejected_by']:
            product['rejected_by'] = str(product['rejected_by'])

        return jsonify({'success': True, 'product': product}), 200
    except Exception as e:
        print(f"Get product error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch product'}), 500

# New API endpoint to get products list
@app.route('/api/products', methods=['GET'])
@limiter.limit("50 per minute")
def get_products():
    try:
        print("GET /api/products called")

        # Check if admin token is provided
        is_admin = False
        token = request.headers.get('Authorization')
        if token and token.startswith('Bearer '):
            try:
                token = token[7:]
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user = users_collection.find_one({'email': data['email']})
                if current_user and current_user.get('role') == 'admin':
                    is_admin = True
            except:
                pass  # Invalid token, treat as regular user

        # Build query based on request parameters
        query = {}

        # Show all products for admin, only approved for regular users (logged in or not)
        # This ensures all users can see approved products on the homepage
        if not is_admin:
            query['status'] = 'approved'

        # Category filtering
        category = request.args.get('category')
        if category:
            # Handle category normalization (convert to lowercase and handle variations)
            category_lower = category.lower().strip()
            if category_lower == 'books& sports':
                category_lower = 'books & sports'
            elif category_lower == 'books & sports':
                # Also match the stored format
                pass
            query['category'] = {'$regex': category_lower, '$options': 'i'}

        # Location filtering (if provided)
        location = request.args.get('location')
        if location:
            query['location'] = {'$regex': location.strip(), '$options': 'i'}

        # Price range filtering
        min_price = request.args.get('min_price')
        max_price = request.args.get('max_price')
        if min_price or max_price:
            price_query = {}
            if min_price:
                try:
                    price_query['$gte'] = float(min_price)
                except ValueError:
                    pass
            if max_price:
                try:
                    price_query['$lte'] = float(max_price)
                except ValueError:
                    pass
            if price_query:
                query['price'] = price_query

        # Rental type filtering
        rental_type = request.args.get('rental_type')
        if rental_type:
            query['rental_type'] = rental_type.strip()

        print(f"Query: {query}")

        products_cursor = products_collection.find(query)
        products = []
        for product in products_cursor:
            product['_id'] = str(product['_id'])
            # Convert ObjectId fields in nested documents if any
            if 'owner_id' in product:
                product['owner_id'] = str(product['owner_id'])
            if 'approved_by' in product and product['approved_by']:
                product['approved_by'] = str(product['approved_by'])
            if 'rejected_by' in product and product['rejected_by']:
                product['rejected_by'] = str(product['rejected_by'])
            products.append(product)

        print(f"Found {len(products)} products matching query")
        return jsonify({'success': True, 'products': products}), 200
    except Exception as e:
        print(f"Get products error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch products'}), 500

# Admin-only decorator
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_collection.find_one({'email': data['email']})
            if not current_user:
                return jsonify({'message': 'Token is invalid'}), 401
            if current_user.get('role') != 'admin':
                return jsonify({'message': 'Admin access required'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# Admin endpoint to get all products with status
@app.route('/api/admin/products', methods=['GET'])
@admin_required
def get_all_products_admin(current_user):
    try:
        # Use aggregation to join with users collection for owner names
        pipeline = [
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'owner_id',
                    'foreignField': '_id',
                    'as': 'owner_info'
                }
            },
            {
                '$unwind': {
                    'path': '$owner_info',
                    'preserveNullAndEmptyArrays': True
                }
            },
            {
                '$project': {
                    '_id': 1,
                    'title': 1,
                    'description': 1,
                    'category': 1,
                    'price': 1,
                    'condition': 1,
                    'rental_type': 1,
                    'location': 1,
                    'status': 1,
                    'created_at': 1,
                    'updated_at': 1,
                    'approved_at': 1,
                    'approved_by': 1,
                    'rejected_by': 1,
                    'rejected_at': 1,
                    'rejection_reason': 1,
                    'images': 1,
                    'cert': 1,
                    'owner_id': 1,
                    'owner_email': 1,
                    'owner_phone': 1,
                    'owner_address': 1,
                    'owner_name': {
                        '$ifNull': [
                            {'$concat': ['$owner_info.firstName', ' ', '$owner_info.lastName']},
                            'Unknown User'
                        ]
                    },
                    'owner_email_display': {
                        '$ifNull': ['$owner_info.email', 'unknown@example.com']
                    }
                }
            }
        ]

        products = list(products_collection.aggregate(pipeline))

        # Convert ObjectId fields to strings
        for product in products:
            product['_id'] = str(product['_id'])
            if 'owner_id' in product:
                product['owner_id'] = str(product['owner_id'])
            if 'approved_by' in product and product['approved_by']:
                product['approved_by'] = str(product['approved_by'])
            if 'rejected_by' in product and product['rejected_by']:
                product['rejected_by'] = str(product['rejected_by'])

        return jsonify({'success': True, 'products': products, 'total': len(products)}), 200
    except Exception as e:
        print(f"Get all products admin error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch products'}), 500

# Admin endpoint to approve/reject products
@app.route('/api/admin/products/<product_id>/approve', methods=['POST'])
@admin_required
def approve_product(current_user, product_id):
    try:
        from bson import ObjectId
        result = products_collection.update_one(
            {'_id': ObjectId(product_id)},
            {
                '$set': {
                    'status': 'approved',
                    'approved_at': datetime.datetime.utcnow(),
                    'approved_by': current_user['_id']
                }
            }
        )

        if result.modified_count > 0:
            return jsonify({'success': True, 'message': 'Product approved successfully'}), 200
        else:
            return jsonify({'success': False, 'message': 'Product not found or already approved'}), 404
    except Exception as e:
        print(f"Approve product error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to approve product'}), 500

@app.route('/api/admin/products/<product_id>/reject', methods=['POST'])
@admin_required
def reject_product(current_user, product_id):
    try:
        from bson import ObjectId

        # Get rejection reason from request
        data = request.get_json()
        reason = data.get('reason', 'No reason provided').strip()

        # Update product status to rejected
        result = products_collection.update_one(
            {'_id': ObjectId(product_id)},
            {
                '$set': {
                    'status': 'rejected',
                    'rejected_at': datetime.datetime.utcnow(),
                    'rejected_by': current_user['_id'],
                    'rejection_reason': reason
                }
            }
        )

        if result.modified_count > 0:
            # Get product details to send notification
            product = products_collection.find_one({'_id': ObjectId(product_id)})

            # Send notification to the product owner via chat
            if product and 'owner_id' in product:
                notification_message = {
                    'product_id': product_id,
                    'sender_id': str(current_user['_id']),
                    'sender_name': f"Admin - {current_user['firstName']} {current_user['lastName']}",
                    'message': f"Your listing '{product.get('title', 'Unknown Item')}' has been rejected. Reason: {reason}",
                    'timestamp': datetime.datetime.utcnow(),
                    'is_admin': True,
                    'is_notification': True
                }

                chats_collection.insert_one(notification_message)

            return jsonify({'success': True, 'message': 'Product rejected successfully'}), 200
        else:
            return jsonify({'success': False, 'message': 'Product not found or already rejected'}), 404
    except Exception as e:
        print(f"Reject product error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to reject product'}), 500

# Admin endpoint to get all users
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_all_users_admin(current_user):
    try:
        users_cursor = users_collection.find({})
        users = []
        for user in users_cursor:
            user['_id'] = str(user['_id'])
            # Remove sensitive fields
            user.pop('password', None)
            user.pop('twoFactorSecret', None)
            user.pop('temp2faSecret', None)
            users.append(user)

        return jsonify({'success': True, 'users': users, 'total': len(users)}), 200
    except Exception as e:
        print(f"Get all users admin error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch users'}), 500

# Admin chat management endpoints
@app.route('/api/admin/chat/messages', methods=['GET'])
@admin_required
def get_all_chat_messages(current_user):
    try:
        # Get all chat messages
        messages_cursor = chats_collection.find({}).sort('timestamp', -1).limit(100)
        messages = []
        for msg in messages_cursor:
            msg['_id'] = str(msg['_id'])
            messages.append(msg)

        return jsonify({
            'success': True,
            'messages': messages
        }), 200

    except Exception as e:
        print(f"Get all chat messages error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch messages'}), 500

@app.route('/api/admin/chat/send', methods=['POST'])
@admin_required
def admin_send_chat_message(current_user):
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        message = data.get('message', '').strip()

        if not product_id or not message:
            return jsonify({'success': False, 'message': 'Product ID and message are required'}), 400

        # Verify product exists
        try:
            from bson import ObjectId
            product = products_collection.find_one({'_id': ObjectId(product_id)})
            if not product:
                return jsonify({'success': False, 'message': 'Product not found'}), 404
        except:
            return jsonify({'success': False, 'message': 'Invalid product ID'}), 400

        # Create admin chat message
        chat_message = {
            'product_id': product_id,
            'sender_id': str(current_user['_id']),
            'sender_name': f"Admin - {current_user['firstName']} {current_user['lastName']}",
            'message': message,
            'timestamp': datetime.datetime.utcnow(),
            'is_admin': True
        }

        # Insert message
        result = chats_collection.insert_one(chat_message)

        if result.inserted_id:
            return jsonify({
                'success': True,
                'message': 'Admin message sent successfully',
                'message_id': str(result.inserted_id)
            }), 201
        else:
            return jsonify({'success': False, 'message': 'Failed to send message'}), 500

    except Exception as e:
        print(f"Admin send chat message error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

# Admin login endpoint
@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.get_json()

        if not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Email and password are required'}), 400

        email = data['email'].lower().strip()
        password = data['password']

        # Fixed admin credentials
        if email == 'admin@renthub.com' and password == 'admin123':
            # Check if admin user exists in database, create if not
            admin_user = users_collection.find_one({'email': email})
            if not admin_user:
                # Create admin user
                admin_data = {
                    'firstName': 'Admin',
                    'lastName': 'User',
                    'email': email,
                    'phone': '+1234567890',
                    'password': generate_password_hash(password),
                    'role': 'admin',
                    'address': '',
                    'bio': 'System Administrator',
                    'profilePicture': '',
                    'isActive': True,
                    'isVerified': True,
                    'twoFactorEnabled': False,
                    'createdAt': datetime.datetime.utcnow(),
                    'updatedAt': datetime.datetime.utcnow(),
                    'lastLoginAt': None,
                    'loginHistory': [],
                    'itemsRented': 0,
                    'itemsListed': 0,
                    'rating': 0.0,
                    'totalRatings': 0
                }
                users_collection.insert_one(admin_data)
                admin_user = admin_data

            # Generate JWT token
            token_payload = {
                'email': admin_user['email'],
                'userId': str(admin_user['_id']),
                'role': 'admin',
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
            }

            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')

            # Return user data
            user_data = {
                'id': str(admin_user['_id']),
                'firstName': admin_user['firstName'],
                'lastName': admin_user['lastName'],
                'email': admin_user['email'],
                'role': 'admin'
            }

            return jsonify({
                'token': token,
                'user': user_data,
                'message': 'Admin login successful'
            }), 200
        else:
            return jsonify({'message': 'Invalid admin credentials'}), 401

    except Exception as e:
        print(f"Admin login error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

# New API endpoint to get category counts
@app.route('/api/categories/counts', methods=['GET'])
def get_category_counts():
    try:
        print("GET /api/categories/counts called")

        # Aggregate products by category
        pipeline = [
            {
                '$group': {
                    '_id': {'$toLower': '$category'},
                    'count': {'$sum': 1}
                }
            }
        ]

        results = list(products_collection.aggregate(pipeline))

        # Convert to a simple dictionary
        counts = {}
        for result in results:
            category_key = result['_id']
            # Handle special cases for category normalization
            if category_key == 'books & sports':
                counts['books& sports'] = result['count']
                counts['books & sports'] = result['count']
            else:
                counts[category_key] = result['count']

        print(f"Category counts: {counts}")
        return jsonify({'success': True, 'counts': counts}), 200
    except Exception as e:
        print(f"Get category counts error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch category counts'}), 500

# Admin endpoint to clear all products (for development/testing)
@app.route('/api/admin/clear-products', methods=['POST'])
@admin_required
def clear_all_products(current_user):
    try:
        result = products_collection.delete_many({})
        deleted_count = result.deleted_count

        print(f"Cleared {deleted_count} products from database")
        return jsonify({
            'success': True,
            'message': f'Successfully cleared {deleted_count} products from database'
        }), 200
    except Exception as e:
        print(f"Clear products error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to clear products'}), 500

# Wishlist API endpoints
@app.route('/api/wishlist', methods=['GET'])
@token_required
def get_wishlist(current_user):
    try:
        wishlist = current_user.get('wishlist', [])
        products = []

        # Fetch product details for wishlist items
        for product_id in wishlist:
            try:
                from bson import ObjectId
                product = products_collection.find_one({'_id': ObjectId(product_id)})
                if product:
                    product['_id'] = str(product['_id'])
                    if 'owner_id' in product:
                        product['owner_id'] = str(product['owner_id'])
                    products.append(product)
            except:
                continue  # Skip invalid product IDs

        return jsonify({
            'success': True,
            'wishlist': products
        }), 200

    except Exception as e:
        print(f"Get wishlist error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch wishlist'}), 500

@app.route('/api/wishlist/add', methods=['POST'])
@token_required
def add_to_wishlist(current_user):
    try:
        data = request.get_json()
        product_id = data.get('product_id')

        if not product_id:
            return jsonify({'success': False, 'message': 'Product ID is required'}), 400

        # Verify product exists
        try:
            from bson import ObjectId
            product = products_collection.find_one({'_id': ObjectId(product_id)})
            if not product:
                return jsonify({'success': False, 'message': 'Product not found'}), 404
        except:
            return jsonify({'success': False, 'message': 'Invalid product ID'}), 400

        # Get current wishlist
        wishlist = current_user.get('wishlist', [])

        # Check if already in wishlist
        if product_id in wishlist:
            return jsonify({'success': False, 'message': 'Product already in wishlist'}), 400

        # Add to wishlist
        wishlist.append(product_id)

        # Update user document
        result = users_collection.update_one(
            {'_id': current_user['_id']},
            {
                '$set': {
                    'wishlist': wishlist,
                    'updatedAt': datetime.datetime.utcnow()
                }
            }
        )

        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Product added to wishlist successfully'
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to add product to wishlist'}), 500

    except Exception as e:
        print(f"Add to wishlist error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/wishlist/remove', methods=['POST'])
@token_required
def remove_from_wishlist(current_user):
    try:
        data = request.get_json()
        product_id = data.get('product_id')

        if not product_id:
            return jsonify({'success': False, 'message': 'Product ID is required'}), 400

        # Get current wishlist
        wishlist = current_user.get('wishlist', [])

        # Check if product is in wishlist
        if product_id not in wishlist:
            return jsonify({'success': False, 'message': 'Product not in wishlist'}), 400

        # Remove from wishlist
        wishlist.remove(product_id)

        # Update user document
        result = users_collection.update_one(
            {'_id': current_user['_id']},
            {
                '$set': {
                    'wishlist': wishlist,
                    'updatedAt': datetime.datetime.utcnow()
                }
            }
        )

        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Product removed from wishlist successfully'
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to remove product from wishlist'}), 500

    except Exception as e:
        print(f"Remove from wishlist error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

# Review API endpoints
@app.route('/api/reviews', methods=['POST'])
@token_required
def submit_review(current_user):
    try:
        data = request.get_json()

        # Required fields
        required_fields = ['product_id', 'rating', 'comment']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'{field} is required'}), 400

        product_id = data['product_id']
        rating = data['rating']
        comment = data['comment'].strip()

        # Validate rating (1-5)
        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                return jsonify({'success': False, 'message': 'Rating must be between 1 and 5'}), 400
        except ValueError:
            return jsonify({'success': False, 'message': 'Rating must be a number'}), 400

        # Validate comment length
        if len(comment) < 10:
            return jsonify({'success': False, 'message': 'Comment must be at least 10 characters long'}), 400
        if len(comment) > 1000:
            return jsonify({'success': False, 'message': 'Comment must be less than 1000 characters'}), 400

        # Verify product exists
        try:
            from bson import ObjectId
            product = products_collection.find_one({'_id': ObjectId(product_id)})
            if not product:
                return jsonify({'success': False, 'message': 'Product not found'}), 404
        except:
            return jsonify({'success': False, 'message': 'Invalid product ID'}), 400

        # Check if user already reviewed this product
        existing_review = reviews_collection.find_one({
            'product_id': product_id,
            'user_id': str(current_user['_id'])
        })
        if existing_review:
            return jsonify({'success': False, 'message': 'You have already reviewed this product'}), 409

        # Create review document
        review_data = {
            'product_id': product_id,
            'user_id': str(current_user['_id']),
            'user_name': f"{current_user['firstName']} {current_user['lastName']}",
            'rating': rating,
            'comment': comment,
            'created_at': datetime.datetime.utcnow(),
            'updated_at': datetime.datetime.utcnow()
        }

        # Insert review
        result = reviews_collection.insert_one(review_data)

        if result.inserted_id:
            # Update product's average rating
            update_product_rating(product_id)
            return jsonify({
                'success': True,
                'message': 'Review submitted successfully',
                'review_id': str(result.inserted_id)
            }), 201
        else:
            return jsonify({'success': False, 'message': 'Failed to submit review'}), 500

    except Exception as e:
        print(f"Submit review error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/reviews/<product_id>', methods=['GET'])
def get_product_reviews(product_id):
    try:
        # Verify product exists
        try:
            from bson import ObjectId
            product = products_collection.find_one({'_id': ObjectId(product_id)})
            if not product:
                return jsonify({'success': False, 'message': 'Product not found'}), 404
        except:
            return jsonify({'success': False, 'message': 'Invalid product ID'}), 400

        # Get reviews for the product
        reviews_cursor = reviews_collection.find({'product_id': product_id}).sort('created_at', -1)
        reviews = []
        for review in reviews_cursor:
            review['_id'] = str(review['_id'])
            reviews.append(review)

        return jsonify({
            'success': True,
            'reviews': reviews,
            'total': len(reviews)
        }), 200

    except Exception as e:
        print(f"Get product reviews error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch reviews'}), 500

@app.route('/api/reviews/user', methods=['GET'])
@token_required
def get_user_reviews(current_user):
    try:
        # Get reviews by the current user
        reviews_cursor = reviews_collection.find({'user_id': str(current_user['_id'])}).sort('created_at', -1)
        reviews = []
        for review in reviews_cursor:
            review['_id'] = str(review['_id'])
            reviews.append(review)

        return jsonify({
            'success': True,
            'reviews': reviews,
            'total': len(reviews)
        }), 200

    except Exception as e:
        print(f"Get user reviews error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch reviews'}), 500

@app.route('/api/reviews/<review_id>', methods=['PUT'])
@token_required
def update_review(current_user, review_id):
    try:
        data = request.get_json()

        # Find the review
        try:
            from bson import ObjectId
            review = reviews_collection.find_one({'_id': ObjectId(review_id)})
            if not review:
                return jsonify({'success': False, 'message': 'Review not found'}), 404
        except:
            return jsonify({'success': False, 'message': 'Invalid review ID'}), 400

        # Check if user owns the review
        if review['user_id'] != str(current_user['_id']):
            return jsonify({'success': False, 'message': 'You can only update your own reviews'}), 403

        # Update fields
        update_data = {'updated_at': datetime.datetime.utcnow()}

        if 'rating' in data:
            try:
                rating = int(data['rating'])
                if rating < 1 or rating > 5:
                    return jsonify({'success': False, 'message': 'Rating must be between 1 and 5'}), 400
                update_data['rating'] = rating
            except ValueError:
                return jsonify({'success': False, 'message': 'Rating must be a number'}), 400

        if 'comment' in data:
            comment = data['comment'].strip()
            if len(comment) < 10:
                return jsonify({'success': False, 'message': 'Comment must be at least 10 characters long'}), 400
            if len(comment) > 1000:
                return jsonify({'success': False, 'message': 'Comment must be less than 1000 characters'}), 400
            update_data['comment'] = comment

        # Update review
        result = reviews_collection.update_one(
            {'_id': ObjectId(review_id)},
            {'$set': update_data}
        )

        if result.modified_count > 0:
            # Update product's average rating if rating changed
            if 'rating' in update_data:
                update_product_rating(review['product_id'])
            return jsonify({'success': True, 'message': 'Review updated successfully'}), 200
        else:
            return jsonify({'success': False, 'message': 'No changes made to review'}), 400

    except Exception as e:
        print(f"Update review error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/reviews/<review_id>', methods=['DELETE'])
@token_required
def delete_review(current_user, review_id):
    try:
        # Find the review
        try:
            from bson import ObjectId
            review = reviews_collection.find_one({'_id': ObjectId(review_id)})
            if not review:
                return jsonify({'success': False, 'message': 'Review not found'}), 404
        except:
            return jsonify({'success': False, 'message': 'Invalid review ID'}), 400

        # Check if user owns the review or is admin
        is_admin = current_user.get('role') == 'admin'
        if review['user_id'] != str(current_user['_id']) and not is_admin:
            return jsonify({'success': False, 'message': 'You can only delete your own reviews'}), 403

        # Delete review
        result = reviews_collection.delete_one({'_id': ObjectId(review_id)})

        if result.deleted_count > 0:
            # Update product's average rating
            update_product_rating(review['product_id'])
            return jsonify({'success': True, 'message': 'Review deleted successfully'}), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to delete review'}), 500

    except Exception as e:
        print(f"Delete review error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

def update_product_rating(product_id):
    """Update the average rating for a product"""
    try:
        # Calculate new average rating
        pipeline = [
            {'$match': {'product_id': product_id}},
            {
                '$group': {
                    '_id': None,
                    'average_rating': {'$avg': '$rating'},
                    'total_ratings': {'$sum': 1}
                }
            }
        ]

        result = list(reviews_collection.aggregate(pipeline))

        if result:
            avg_rating = round(result[0]['average_rating'], 1)
            total_ratings = result[0]['total_ratings']
        else:
            avg_rating = 0.0
            total_ratings = 0

        # Update product
        products_collection.update_one(
            {'_id': ObjectId(product_id)},
            {
                '$set': {
                    'rating': avg_rating,
                    'totalRatings': total_ratings,
                    'updated_at': datetime.datetime.utcnow()
                }
            }
        )
    except Exception as e:
        print(f"Update product rating error: {str(e)}")

# Cart API endpoints
@app.route('/api/cart', methods=['GET'])
@token_required
def get_cart(current_user):
    try:
        cart = current_user.get('cart', [])
        products = []

        # Fetch product details for cart items
        for item in cart:
            try:
                from bson import ObjectId
                product = products_collection.find_one({'_id': ObjectId(item['product_id'])})
                if product:
                    product['_id'] = str(product['_id'])
                    if 'owner_id' in product:
                        product['owner_id'] = str(product['owner_id'])
                    # Add cart-specific info
                    product['cart_quantity'] = item.get('quantity', 1)
                    product['cart_duration'] = item.get('duration', '1 day')
                    product['cart_unit'] = item.get('unit', 'day')
                    products.append(product)
            except:
                continue  # Skip invalid product IDs

        return jsonify({
            'success': True,
            'cart': products
        }), 200

    except Exception as e:
        print(f"Get cart error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch cart'}), 500

@app.route('/api/cart/add', methods=['POST'])
@token_required
def add_to_cart(current_user):
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)
        duration = data.get('duration', '1')
        unit = data.get('unit', 'day')

        if not product_id:
            return jsonify({'success': False, 'message': 'Product ID is required'}), 400

        # Verify product exists
        try:
            from bson import ObjectId
            product = products_collection.find_one({'_id': ObjectId(product_id)})
            if not product:
                return jsonify({'success': False, 'message': 'Product not found'}), 404
        except:
            return jsonify({'success': False, 'message': 'Invalid product ID'}), 400

        # Get current cart
        cart = current_user.get('cart', [])

        # Check if already in cart
        existing_item = None
        for item in cart:
            if item['product_id'] == product_id and item.get('duration') == duration and item.get('unit') == unit:
                existing_item = item
                break

        if existing_item:
            # Update quantity
            existing_item['quantity'] = existing_item.get('quantity', 1) + quantity
        else:
            # Add new item
            cart_item = {
                'product_id': product_id,
                'quantity': quantity,
                'duration': duration,
                'unit': unit,
                'added_at': datetime.datetime.utcnow()
            }
            cart.append(cart_item)

        # Update user document
        result = users_collection.update_one(
            {'_id': current_user['_id']},
            {
                '$set': {
                    'cart': cart,
                    'updatedAt': datetime.datetime.utcnow()
                }
            }
        )

        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Product added to cart successfully'
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to add product to cart'}), 500

    except Exception as e:
        print(f"Add to cart error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/cart/remove', methods=['POST'])
@token_required
def remove_from_cart(current_user):
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        duration = data.get('duration', '1')
        unit = data.get('unit', 'day')

        if not product_id:
            return jsonify({'success': False, 'message': 'Product ID is required'}), 400

        # Get current cart
        cart = current_user.get('cart', [])

        # Find and remove item
        cart = [item for item in cart if not (
            item['product_id'] == product_id and
            item.get('duration') == duration and
            item.get('unit') == unit
        )]

        # Update user document
        result = users_collection.update_one(
            {'_id': current_user['_id']},
            {
                '$set': {
                    'cart': cart,
                    'updatedAt': datetime.datetime.utcnow()
                }
            }
        )

        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Product removed from cart successfully'
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to remove product from cart'}), 500

    except Exception as e:
        print(f"Remove from cart error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/cart/update', methods=['POST'])
@token_required
def update_cart_item(current_user):
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)
        duration = data.get('duration', '1')
        unit = data.get('unit', 'day')

        if not product_id:
            return jsonify({'success': False, 'message': 'Product ID is required'}), 400

        if quantity < 1:
            return jsonify({'success': False, 'message': 'Quantity must be at least 1'}), 400

        # Get current cart
        cart = current_user.get('cart', [])

        # Find and update item
        item_found = False
        for item in cart:
            if item['product_id'] == product_id and item.get('duration') == duration and item.get('unit') == unit:
                item['quantity'] = quantity
                item_found = True
                break

        if not item_found:
            return jsonify({'success': False, 'message': 'Item not found in cart'}), 404

        # Update user document
        result = users_collection.update_one(
            {'_id': current_user['_id']},
            {
                '$set': {
                    'cart': cart,
                    'updatedAt': datetime.datetime.utcnow()
                }
            }
        )

        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Cart item updated successfully'
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to update cart item'}), 500

    except Exception as e:
        print(f"Update cart item error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/cart/clear', methods=['POST'])
@token_required
def clear_cart(current_user):
    try:
        # Clear cart
        result = users_collection.update_one(
            {'_id': current_user['_id']},
            {
                '$set': {
                    'cart': [],
                    'updatedAt': datetime.datetime.utcnow()
                }
            }
        )

        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Cart cleared successfully'
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to clear cart'}), 500

    except Exception as e:
        print(f"Clear cart error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

# Chat API endpoints
@app.route('/api/chat/send', methods=['POST'])
@token_required
def send_chat_message(current_user):
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        message = data.get('message', '').strip()

        if not product_id or not message:
            return jsonify({'success': False, 'message': 'Product ID and message are required'}), 400

        # Verify product exists
        try:
            from bson import ObjectId
            product = products_collection.find_one({'_id': ObjectId(product_id)})
            if not product:
                return jsonify({'success': False, 'message': 'Product not found'}), 404
        except:
            return jsonify({'success': False, 'message': 'Invalid product ID'}), 400

        # Create chat message
        chat_message = {
            'product_id': product_id,
            'sender_id': str(current_user['_id']),
            'sender_name': f"{current_user['firstName']} {current_user['lastName']}",
            'message': message,
            'timestamp': datetime.datetime.utcnow()
        }

        # Insert message
        result = chats_collection.insert_one(chat_message)

        if result.inserted_id:
            return jsonify({
                'success': True,
                'message': 'Message sent successfully',
                'message_id': str(result.inserted_id)
            }), 201
        else:
            return jsonify({'success': False, 'message': 'Failed to send message'}), 500

    except Exception as e:
        print(f"Send chat message error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/chat/messages/<product_id>', methods=['GET'])
@token_required
def get_chat_messages(current_user, product_id):
    try:
        # Verify product exists
        try:
            from bson import ObjectId
            product = products_collection.find_one({'_id': ObjectId(product_id)})
            if not product:
                return jsonify({'success': False, 'message': 'Product not found'}), 404
        except:
            return jsonify({'success': False, 'message': 'Invalid product ID'}), 400

        # Get messages for this product
        messages_cursor = chats_collection.find({'product_id': product_id}).sort('timestamp', 1)
        messages = []
        for msg in messages_cursor:
            msg['_id'] = str(msg['_id'])
            messages.append(msg)

        return jsonify({
            'success': True,
            'messages': messages
        }), 200

    except Exception as e:
        print(f"Get chat messages error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch messages'}), 500

if __name__ == '__main__':
    # Create indexes for better performance
    users_collection.create_index([("email", 1)], unique=True)
    users_collection.create_index([("phone", 1)], unique=True)

    # Add products collection index
    products_collection.create_index([("category", 1)])

    # Add reviews collection indexes
    reviews_collection.create_index([("product_id", 1)])
    reviews_collection.create_index([("user_id", 1)])

    # Add chats collection index
    chats_collection.create_index([("product_id", 1)])
    chats_collection.create_index([("timestamp", 1)])

    print("RentHub API Server Starting...")
    print("Endpoints available:")
    print("- POST /api/signup - User registration")
    print("- POST /api/login - User login")
    print("- GET /api/profile - Get user profile")
    print("- PUT /api/profile - Update user profile")
    print("- POST /api/change-password - Change password")
    print("- POST /api/toggle-2fa - Toggle two-factor authentication")
    print("- GET /api/login-history - Get login history")
    print("- POST /api/deactivate-account - Deactivate user account")
    print("- GET /api/health - Health check")
    print("- POST /api/products - Create product listing")
    print("- GET /api/products - Get product listings")
    print("- GET /api/categories/counts - Get category counts")
    print("- POST /api/admin/login - Admin login")
    print("- GET /api/admin/products - Get all products (admin)")
    print("- POST /api/admin/products/<id>/approve - Approve product (admin)")
    print("- POST /api/admin/products/<id>/reject - Reject product (admin)")
    print("- GET /api/admin/users - Get all users (admin)")
    print("- POST /api/reviews - Submit review")
    print("- GET /api/reviews/<product_id> - Get product reviews")
    print("- GET /api/reviews/user - Get user reviews")
    print("- PUT /api/reviews/<review_id> - Update review")
    print("- DELETE /api/reviews/<review_id> - Delete review")
    print("- GET /api/cart - Get user cart")
    print("- POST /api/cart/add - Add item to cart")
    print("- POST /api/cart/remove - Remove item from cart")
    print("- POST /api/cart/update - Update cart item")
    print("- POST /api/cart/clear - Clear cart")
    print("- POST /api/chat/send - Send chat message")
    print("- GET /api/chat/messages/<product_id> - Get chat messages")

    app.run(debug=True, host='0.0.0.0', port=5000)
