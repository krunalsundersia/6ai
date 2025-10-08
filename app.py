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
        
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    
except Exception as e:
    logger.error(f"Error loading environment variables: {e}")

# Try to import optional dependencies
try:
    from openai import OpenAI
    from io import BytesIO
    from authlib.integrations.flask_client import OAuth
    from functools import wraps
    
    # Initialize OAuth only if Google credentials are available
    if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
        oauth = OAuth(app)
        google = oauth.register(
            name='google',
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            server_metadata_url='https://accounts.google.com/.well-known/openid_configuration',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
        logger.info("Google OAuth configured successfully")
    else:
        logger.warning("Google OAuth not configured - missing client ID or secret")
        
except ImportError as e:
    logger.error(f"Missing dependency: {e}")
except Exception as e:
    logger.error(f"Error initializing OAuth: {e}")

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    try:
        user_info = session.get('user', {})
        return render_template('index.html', user=user_info)
    except Exception as e:
        logger.error(f"Error rendering index: {e}")
        return f"Error loading application: {str(e)}", 500

@app.route('/login')
def login():
    try:
        # If user is already logged in, redirect to home
        if 'user' in session:
            return redirect('/')
        
        # Check if Google OAuth is configured
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            logger.warning("Google OAuth not configured, using test login")
            return render_template('login.html', google_configured=False)
        
        return render_template('login.html', google_configured=True)
    except Exception as e:
        logger.error(f"Error rendering login: {e}")
        return f"Error loading login page: {str(e)}", 500

# Google OAuth routes
@app.route('/auth/google')
def google_auth():
    """Initiate Google OAuth flow"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return redirect('/login')
    
    try:
        # Generate a state token for security
        state = str(uuid.uuid4())
        session['oauth_state'] = state
        
        redirect_uri = url_for('google_callback', _external=True)
        return google.authorize_redirect(redirect_uri, state=state)
    except Exception as e:
        logger.error(f"Error initiating Google OAuth: {e}")
        return redirect('/login?error=oauth_init_failed')

@app.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    try:
        # Verify state parameter for security
        state = request.args.get('state')
        if not state or state != session.get('oauth_state'):
            logger.warning("Invalid state parameter in OAuth callback")
            return redirect('/login?error=invalid_state')
        
        # Remove state from session
        session.pop('oauth_state', None)
        
        # Get the token from Google
        token = google.authorize_access_token()
        
        # Get user info from Google
        user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
        
        # Store user information in session
        session['user'] = {
            'id': user_info.get('sub'),
            'name': user_info.get('name'),
            'email': user_info.get('email'),
            'picture': user_info.get('picture'),
            'provider': 'google'
        }
        
        logger.info(f"User logged in: {user_info.get('email')}")
        return redirect('/')
        
    except Exception as e:
        logger.error(f"Error in Google OAuth callback: {e}")
        return redirect('/login?error=oauth_failed')

# Simple test authentication (fallback)
@app.route('/test-login')
def test_login():
    session['user'] = {
        'id': 'test-user-123',
        'name': 'Test User',
        'email': 'test@example.com',
        'picture': None,
        'provider': 'test'
    }
    logger.info("Test user logged in")
    return redirect('/')

@app.route('/logout')
def logout():
    user_email = session.get('user', {}).get('email', 'Unknown')
    session.pop('user', None)
    session.pop('oauth_state', None)
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
        "user_authenticated": 'user' in session,
        "current_user": session.get('user', {}).get('email') if 'user' in session else None
    })

# Health check endpoint
@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "flask_working": True,
        "user_authenticated": 'user' in session,
        "openrouter_configured": bool(OPENROUTER_API_KEY),
        "google_oauth_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        "current_user": session.get('user', {}).get('email') if 'user' in session else None
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    logger.info("Starting Flask application...")
    logger.info(f"OpenRouter API Key: {'✓ Configured' if OPENROUTER_API_KEY else '✗ Missing'}")
    logger.info(f"Google OAuth: {'✓ Configured' if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET else '✗ Missing'}")
    logger.info(f"Server running on http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
