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
    FRONTEND_URL=os.environ.get('FRONTEND_URL', '/'),

    # Secure Session Settings (recommended for Vercel/HTTPS)
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax', 
)

# Enable CORS with credentials support (necessary for session cookies)
CORS(app, supports_credentials=True)

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

# Token management (simplified)
TOKEN_LIMIT = 300000
tokens_used = 0
KEY = os.getenv("OPENROUTER_API_KEY")

# AI Models configuration
MODELS = {
    "logic": {"name": "Logic AI", "description": "analytical, structured, step-by-step"},
    "creative": {"name": "Creative AI", "description": "poetic, metaphorical, emotional"},
    "technical": {"name": "Technical AI", "description": "precise, technical, detail-oriented"},
    "philosophical": {"name": "Philosophical AI", "description": "deep, reflective, abstract"},
    "humorous": {"name": "Humorous AI", "description": "witty, lighthearted, engaging"}
}

SYSTEM_PROMPTS = {
    "logic": "You are Logic AI — analytical, structured, step-by-step. Provide clear, logical reasoning and systematic approaches. Break down complex problems into manageable steps and explain your reasoning clearly.",
    "creative": "You are Creative AI — poetic, metaphorical, emotional. Use imaginative language and creative perspectives. Think outside the box and provide innovative solutions with vivid descriptions.",
    "technical": "You are Technical AI — precise, technical, detail-oriented. Provide accurate, detailed, and technically sound responses, focusing on facts, specifications, and practical applications.",
    "philosophical": "You are Philosophical AI — deep, reflective, abstract. Offer profound insights, explore existential questions, and provide thoughtful, nuanced perspectives.",
    "humorous": "You are Humorous AI — witty, lighthearted, engaging. Deliver responses with humor, clever analogies, and a playful tone while remaining relevant and informative."
}

# Helper functions
def count_tokens(text):
    if not text:
        return 0
    return len(text.split()) + len(text) // 4

def extract_text_from_pdf(file_content):
    try:
        pdf_file = BytesIO(file_content)
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text.strip()
    except Exception as e:
        logger.error(f"PDF extraction error: {str(e)}")
        return None

# ----------------------------------------------------------------------
# 🔑 OAUTH ROUTES - WITH PROXY FIX AND EXPLICIT REDIRECT URI 🔑
# ----------------------------------------------------------------------

@app.route('/')
def index():
    """Simple API status check."""
    return jsonify({
        "status": "running", 
        "service": "Pentad-Chat API",
        "authenticated": bool(session.get('user'))
    })

@app.route('/api/login/google')
def google_login():
    try:
        if not app.config.get("GOOGLE_CLIENT_ID"):
            return jsonify(error="OAuth not configured"), 500
            
        # Use url_for with _external=True. ProxyFix ensures this is HTTPS.
        redirect_uri = url_for('google_authorize', _external=True)
        
        return oauth.google.authorize_redirect(redirect_uri)
        
    except Exception as e:
        logger.error(f"Google login error: {str(e)}")
        return jsonify(error="Authentication error during redirect"), 500

@app.route('/api/login/google/authorize')
def google_authorize():
    try:
        # Re-calculate redirect_uri for token exchange validation
        redirect_uri = url_for('google_authorize', _external=True)
        
        # Pass the redirect_uri explicitly to prevent MismatchingStateError
        token = oauth.google.authorize_access_token(redirect_uri=redirect_uri)
        
        if not token:
            raise Exception("No access token received.")
            
        resp = oauth.google.get('userinfo')
        resp.raise_for_status()
        user_info = resp.json()
        
        session['user'] = {
            'name': user_info.get('name', ''),
            'email': user_info.get('email'),
            'picture': user_info.get('picture', ''),
            'provider': 'google'
        }
        
        # Redirect back to the frontend URL defined in environment variables
        frontend_url = app.config.get('FRONTEND_URL', request.host_url)
        return redirect(frontend_url)
    
    except Exception as e:
        # Check Vercel logs for the specific error (e.g., MismatchingStateError)
        logger.error(f"Google auth error in token exchange: {str(e)}") 
        return jsonify(error=f"Authentication failed. Check Vercel logs for detail."), 400

@app.route('/api/logout')
def logout():
    session.pop('user', None)
    return jsonify(message="Logged out successfully")

@app.route('/api/auth/status')
def auth_status():
    return jsonify({
        'authenticated': bool(session.get('user')),
        'user': session.get('user')
    })

# ----------------------------------------------------------------------
# 🤖 AI ROUTES 
# ----------------------------------------------------------------------

def generate(bot_name: str, system: str, user: str, file_contents: list = None):
    # This function needs access to the global variables
    global tokens_used, KEY, TOKEN_LIMIT, MODELS 

    if not KEY:
        yield f"data: {json.dumps({'bot': bot_name, 'error': 'OpenRouter API key not configured'})}\n\n"
        return
        
    try:
        # Check if user is logged in
        if not session.get('user'):
            yield f"data: {json.dumps({'bot': bot_name, 'error': 'Please login first'})}\n\n"
            return

        # (Prompt and token logic omitted for brevity, assumed correct)
        
        # ... (API Request Logic)
        
    except Exception as exc:
        logger.error(f"Generation error for {bot_name}: {str(exc)}")
        yield f"data: {json.dumps({'bot': bot_name, 'error': 'Generation failed'})}\n\n"

@app.route("/api/chat", methods=["POST"])
def chat():
    try:
        if not session.get('user'):
            return jsonify(error="Please login first"), 401
        
        data = request.json or {}
        prompt = data.get("prompt", "").strip()
        
        if not prompt:
            return jsonify(error="Empty prompt"), 400
        
        # (Event stream logic omitted for brevity, assumed correct)

        def event_stream():
            for bot_name in MODELS.keys():
                generator = generate(bot_name, SYSTEM_PROMPTS[bot_name], prompt)
                for chunk in generator:
                    yield chunk
            yield f"data: {json.dumps({'all_done': True, 'tokens': tokens_used})}\n\n"

        return Response(
            event_stream(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            },
        )
    
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route("/api/asklurk", methods=["POST"])
def asklurk():
    try:
        if not session.get('user'):
            return jsonify(best="", error="Please login first"), 401
        
        # (Synthesis logic omitted for brevity, assumed correct)
        
        return jsonify(best="Synthesized Answer")
        
    except Exception as e:
        logger.error(f"AskLurk error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route("/api/tokens", methods=["GET"])
def get_tokens():
    return jsonify({
        "tokens_used": tokens_used,
        "token_limit": TOKEN_LIMIT,
        "remaining_tokens": TOKEN_LIMIT - tokens_used
    })

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "api_key_configured": bool(KEY),
        "oauth_configured": bool(app.config.get("GOOGLE_CLIENT_ID")),
        "authenticated_users": 1 if session.get('user') else 0
    })

# ----------------------------------------------------------------------
# ⚙️ VERCEL ENTRY POINT
# ----------------------------------------------------------------------
# Vercel needs this function to know how to instantiate your Flask application
def create_app():
    return app

if __name__ == '__main__':
    # For local development
    app.run(debug=True)
