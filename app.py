import os
import json
import logging
import uuid
from flask import Flask, request, Response, jsonify, session, url_for, redirect
from flask_cors import CORS
import requests
import PyPDF2
from io import BytesIO
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix # ⚠️ ESSENTIAL FIX FOR VERCEL

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# --- 🎯 CRITICAL FIX FOR VERCEL/PROXY ENVIRONMENTS 🎯 ---
# This ensures Flask correctly recognizes HTTPS and trusts Vercel's proxy headers 
# (X-Forwarded-Proto, X-Forwarded-Host). This is VITAL for session cookie security 
# and correct URL generation in OAuth.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1)

# Configuration
app.config.update(
    # Set a robust secret key; must be set as SESSION_SECRET on Vercel
    SECRET_KEY=os.environ.get("SESSION_SECRET", "default-insecure-secret-please-change"),
    
    # OAuth Credentials - Must be set as environment variables on Vercel
    GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID"),
    GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET"),
    
    # URL of your deployed frontend (e.g., https://your-app.vercel.app)
    FRONTEND_URL=os.environ.get('FRONTEND_URL', '/'),

    # Secure Session Settings (recommended for Vercel/HTTPS)
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax', 
)

# Enable CORS with credentials support (necessary for session cookies)
CORS(app, supports_credentials=True, origins=[app.config.get('FRONTEND_URL')])

# Initialize OAuth
oauth = OAuth(app)

# OAuth Registration
try:
    google = oauth.register(
        name='google',
        client_id=app.config["GOOGLE_CLIENT_ID"],
        client_secret=app.config["GOOGLE_CLIENT_SECRET"],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )
except Exception as e:
    logger.error(f"OAuth registration failed: {str(e)}")
    google = None

# Token management
TOKEN_LIMIT = 300000
tokens_used = 0
KEY = os.getenv("OPENROUTER_API_KEY")

# AI Models configuration (full definitions)
MODELS = {
    "logic": {"name": "Logic AI", "description": "analytical, structured, step-by-step"},
    "creative": {"name": "Creative AI", "description": "poetic, metaphorical, emotional"},
    "technical": {"name": "Technical AI", "description": "precise, technical, detail-oriented"},
    "philosophical": {"name": "Philosophical AI", "description": "deep, reflective, abstract"},
    "humorous": {"name": "Humorous AI", "description": "witty, lighthearted, engaging"}
}
SYSTEM_PROMPTS = {
    "logic": "You are Logic AI — analytical, structured, step-by-step...",
    "creative": "You are Creative AI — poetic, metaphorical, emotional...",
    "technical": "You are Technical AI — precise, technical, detail-oriented...",
    "philosophical": "You are Philosophical AI — deep, reflective, abstract...",
    "humorous": "You are Humorous AI — witty, lighthearted, engaging..."
}

# --- Helper Functions ---
def count_tokens(text):
    if not text: return 0
    return len(text.split()) + len(text) // 4

# --- API Routes ---

@app.route('/')
def index():
    """Simple API root for health check."""
    return jsonify({
        "status": "running", 
        "service": "Pentad-Chat API",
        "authenticated": 'user' in session
    })

# ----------------------------------------------------------------------
# 🔑 OAUTH & AUTHENTICATION ROUTES
# ----------------------------------------------------------------------

@app.route('/api/login/google')
def google_login():
    if not google:
        return jsonify(error="OAuth not configured on the server"), 500
    
    try:
        # Use url_for with _external=True. ProxyFix ensures this is HTTPS.
        redirect_uri = url_for('google_authorize', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)
    except Exception as e:
        logger.error(f"Google login redirect error: {str(e)}")
        return jsonify(error="Authentication redirect failed"), 500

@app.route('/api/login/google/authorize')
def google_authorize():
    try:
        # Pass the same redirect_uri to prevent MismatchingStateError
        redirect_uri = url_for('google_authorize', _external=True)
        token = oauth.google.authorize_access_token(redirect_uri=redirect_uri)
        
        resp = oauth.google.get('userinfo', token=token)
        resp.raise_for_status()
        user_info = resp.json()
        
        session['user'] = {
            'name': user_info.get('name', ''),
            'email': user_info.get('email'),
            'picture': user_info.get('picture', ''),
            'provider': 'google'
        }
        
        # Redirect back to the frontend URL
        return redirect(app.config.get('FRONTEND_URL'))
    
    except Exception as e:
        logger.error(f"Google authorization error: {str(e)}", exc_info=True) 
        return redirect(f"{app.config.get('FRONTEND_URL')}?error=auth_failed")

@app.route('/api/logout')
def logout():
    session.pop('user', None)
    return jsonify(message="Logged out successfully")

@app.route('/api/auth/status')
def auth_status():
    if 'user' in session:
        return jsonify({'authenticated': True, 'user': session['user']})
    return jsonify({'authenticated': False, 'user': None})

# ----------------------------------------------------------------------
# 🤖 AI & CORE FUNCTIONALITY ROUTES 
# ----------------------------------------------------------------------

def generate(bot_name: str, system: str, user: str):
    global tokens_used
    if not KEY:
        yield f'data: {json.dumps({"bot": bot_name, "error": "API key not configured"})}\n\n'
        return
    
    if not session.get('user'):
        yield f'data: {json.dumps({"bot": bot_name, "error": "Please login first"})}\n\n'
        return
    
    # ... (Full API request logic from your original file)
    # This section remains the same.
    
    yield f'data: {json.dumps({"bot": bot_name, "done": True})}\n\n'


@app.route("/api/chat", methods=["POST"])
def chat():
    if not session.get('user'):
        return jsonify(error="Authentication required"), 401
    
    data = request.json or {}
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify(error="Prompt cannot be empty"), 400

    def event_stream():
        # ... (Full event stream logic from your original file)
        # This section remains the same.
        yield f"data: {json.dumps({'all_done': True, 'tokens': tokens_used})}\n\n"

    return Response(event_stream(), mimetype="text/event-stream")


@app.route("/api/asklurk", methods=["POST"])
def asklurk():
    if not session.get('user'):
        return jsonify(error="Authentication required"), 401
    
    # ... (Full AskLurk synthesis logic from your original file)
    # This section remains the same.
    
    return jsonify(best="Synthesized Answer", tokens_used=tokens_used)


@app.route("/api/tokens", methods=["GET"])
def get_tokens():
    return jsonify({
        "tokens_used": tokens_used,
        "token_limit": TOKEN_LIMIT,
        "remaining_tokens": TOKEN_LIMIT - tokens_used
    })

@app.route("/api/health")
def health():
    return jsonify(status="ok", api_key_configured=bool(KEY))


# --- Vercel Entry Point ---
def create_app():
   return app

# --- Local Development ---
if __name__ == '__main__':
    # Note: For local testing, OAuth may require http://localhost in Google Cloud Console.
    # Vercel deployment will use the real https:// URL.
    app.run(debug=True, port=5001)
