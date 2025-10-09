import os
import json
import logging
import sys
import uuid
from flask import Flask, request, Response, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables first
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "fallback-secret-key-123")
CORS(app)

# Check for required environment variables
try:
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not OPENROUTER_API_KEY:
        logger.warning("OPENROUTER_API_KEY not found in environment variables")
        
except Exception as e:
    logger.error(f"Error loading environment variables: {e}")

# Try to import optional dependencies
try:
    from openai import OpenAI
    from io import BytesIO
    
except ImportError as e:
    logger.error(f"Missing dependency: {e}")
except Exception as e:
    logger.error(f"Error initializing dependencies: {e}")

# Firebase Admin SDK for backend verification (optional but recommended)
try:
    import firebase_admin
    from firebase_admin import credentials, auth
    
    # Initialize Firebase Admin
    cred = credentials.Certificate("firebase-service-account.json")  # You'll need to download this
    firebase_admin.initialize_app(cred)
    logger.info("Firebase Admin SDK initialized")
except ImportError:
    logger.warning("Firebase Admin SDK not installed - backend verification disabled")
except Exception as e:
    logger.warning(f"Firebase Admin initialization failed: {e}")

def login_required(f):
    """Decorator to check if user is authenticated"""
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is in session (basic check)
        if 'user' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    try:
        user_info = session.get('user', {})
        return render_template('app.html', user=user_info)
    except Exception as e:
        logger.error(f"Error rendering index: {e}")
        return f"Error loading application: {str(e)}", 500

@app.route('/login')
def login():
    """Serve the Firebase login page"""
    try:
        # If user is already logged in, redirect to main app
        if 'user' in session:
            return redirect('/')
        return render_template('login.html')
    except Exception as e:
        logger.error(f"Error rendering login: {e}")
        return f"Error loading login page: {str(e)}", 500

@app.route('/auth/verify', methods=['POST'])
def verify_auth():
    """Verify Firebase ID token and create session"""
    try:
        data = request.get_json()
        id_token = data.get('idToken')
        
        if not id_token:
            return jsonify({"error": "No ID token provided"}), 400
        
        # Verify the Firebase ID token
        try:
            decoded_token = auth.verify_id_token(id_token)
            user_id = decoded_token['uid']
            email = decoded_token.get('email', '')
            name = decoded_token.get('name', '')
            
            # Store user info in session
            session['user'] = {
                'id': user_id,
                'email': email,
                'name': name,
                'authenticated': True
            }
            
            logger.info(f"User authenticated: {email}")
            return jsonify({
                "status": "success",
                "message": "Authentication successful",
                "user": session['user']
            })
            
        except Exception as firebase_error:
            logger.error(f"Firebase token verification failed: {firebase_error}")
            return jsonify({"error": "Invalid authentication token"}), 401
            
    except Exception as e:
        logger.error(f"Error verifying auth: {e}")
        return jsonify({"error": "Authentication failed"}), 500

@app.route('/auth/simple-login', methods=['POST'])
def simple_login():
    """Simple session-based login (fallback if Firebase Admin not setup)"""
    try:
        data = request.get_json()
        user_email = data.get('email', 'user@example.com')
        user_name = data.get('name', 'User')
        
        # Store basic user info in session
        session['user'] = {
            'id': str(uuid.uuid4()),
            'email': user_email,
            'name': user_name,
            'authenticated': True
        }
        
        logger.info(f"User logged in (simple): {user_email}")
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "user": session['user']
        })
        
    except Exception as e:
        logger.error(f"Error in simple login: {e}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    user_email = session.get('user', {}).get('email', 'Unknown')
    session.clear()
    logger.info(f"User logged out: {user_email}")
    return redirect('/login')

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    try:
        user_info = session.get('user', {})
        return jsonify({
            "status": "success",
            "user": user_info
        })
    except Exception as e:
        logger.error(f"Error getting profile: {e}")
        return jsonify({"error": "Failed to get profile"}), 500

@app.route('/test-api')
def test_api():
    return jsonify({
        "status": "success",
        "message": "API is working",
        "user_authenticated": 'user' in session
    })

# Health check endpoint
@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "flask_working": True,
        "openrouter_configured": bool(OPENROUTER_API_KEY),
        "user_authenticated": 'user' in session
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    logger.info("Starting Flask application...")
    logger.info(f"OpenRouter API Key: {'✓ Configured' if OPENROUTER_API_KEY else '✗ Missing'}")
    logger.info(f"Server running on http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
