import os
import json
import logging
import uuid
from functools import wraps
from flask import Flask, request, Response, jsonify, render_template, session, url_for, redirect
from flask_cors import CORS
import requests
import PyPDF2
from io import BytesIO
from authlib.integrations.flask_client import OAuth

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config.update(
    SECRET_KEY=os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production"),
    GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID"),
    GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET"),
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

CORS(app)

# Initialize OAuth
oauth = OAuth(app)

# Check required environment variables
required_env_vars = ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "SESSION_SECRET"]
missing_vars = [var for var in required_env_vars if not os.environ.get(var)]

if missing_vars:
    logger.warning(f"Missing environment variables: {', '.join(missing_vars)}")
    logger.warning("Authentication may not work properly")

# OAuth Registrations
try:
    google = oauth.register(
        name='google',
        client_id=app.config["GOOGLE_CLIENT_ID"],
        client_secret=app.config["GOOGLE_CLIENT_SECRET"],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile',
            'prompt': 'select_account'
        },
        authorize_params={'access_type': 'online'},
    )
    logger.info("Google OAuth client registered successfully")
except Exception as e:
    logger.error(f"OAuth registration failed: {str(e)}")
    google = None

# Token management
TOKEN_LIMIT = 300000
tokens_used = 0

def count_tokens(text):
    """Approximate token count by splitting on spaces"""
    if not text:
        return 0
    return len(text.split()) + len(text) // 4

# Initialize OpenRouter API key
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

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            return jsonify(error="Authentication required. Please log in first."), 401
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    user = session.get('user')
    return render_template('index.html', user=user)

@app.route('/login/google')
def google_login():
    try:
        # Check if OAuth is properly configured
        if not app.config.get("GOOGLE_CLIENT_ID") or not app.config.get("GOOGLE_CLIENT_SECRET"):
            logger.error("Google OAuth not configured - missing client ID or secret")
            return render_template('error.html', error="Authentication not configured. Please contact administrator."), 500
            
        google_client = oauth.create_client('google')
        if not google_client:
            logger.error("Failed to create Google OAuth client")
            return render_template('error.html', error="Authentication service unavailable."), 500
            
        redirect_uri = url_for('google_authorize', _external=True)
        logger.info(f"Initiating Google OAuth flow with redirect: {redirect_uri}")
        return google_client.authorize_redirect(redirect_uri)
        
    except Exception as e:
        logger.error(f"Google login initialization error: {str(e)}")
        return render_template('error.html', error=f"Authentication error: {str(e)}"), 500

@app.route('/login/google/authorize')
def google_authorize():
    try:
        google_client = oauth.create_client('google')
        if not google_client:
            return render_template('error.html', error="Authentication client error"), 500
            
        # Get access token
        token = google_client.authorize_access_token()
        if not token:
            logger.error("No access token received from Google")
            return render_template('error.html', error="Failed to get access token from Google"), 400
            
        logger.info("Successfully obtained access token from Google")
        
        # Get user info
        resp = google_client.get('userinfo')
        if resp.status != 200:
            logger.error(f"Failed to get user info from Google: {resp.status}")
            return render_template('error.html', error="Failed to get user information from Google"), 400
            
        user_info = resp.json()
        logger.info(f"Received user info: {user_info.get('email')}")
        
        # Validate required user info
        if not user_info.get('email'):
            logger.error("Email not provided by Google in user info")
            return render_template('error.html', error="Email not provided by Google"), 400
            
        # Store user in session
        session['user'] = {
            'name': user_info.get('name', ''),
            'email': user_info.get('email'),
            'picture': user_info.get('picture', ''),
            'provider': 'google'
        }
        
        # Set session as permanent
        session.permanent = True
        
        logger.info(f"User successfully logged in: {user_info.get('email')}")
        return redirect(url_for('index'))
    
    except Exception as e:
        logger.error(f"Google authorization error: {str(e)}")
        return render_template('error.html', error=f"Authentication failed: {str(e)}"), 400

@app.route('/logout')
def logout():
    user_email = session.get('user', {}).get('email', 'Unknown')
    session.pop('user', None)
    session.clear()
    logger.info(f"User logged out: {user_email}")
    return redirect(url_for('index'))

@app.route('/auth/status')
def auth_status():
    """Check authentication status"""
    return jsonify({
        'authenticated': bool(session.get('user')),
        'user': session.get('user'),
        'oauth_configured': bool(app.config.get("GOOGLE_CLIENT_ID") and app.config.get("GOOGLE_CLIENT_SECRET")),
        'session_secret_set': bool(app.config.get("SECRET_KEY")),
    })

# File processing
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

# AI Generation using direct HTTP requests
def generate(bot_name: str, system: str, user: str, file_contents: list = None):
    global tokens_used
    if not KEY:
        yield f"data: {json.dumps({'bot': bot_name, 'error': 'OpenRouter API key not configured'})}\n\n"
        return
        
    try:
        full_user_prompt = user
        if file_contents:
            file_context = "\n\n".join(file_contents)
            full_user_prompt = f"{user}\n\nAttached files content:\n{file_context}"
        
        # Check token limit
        if tokens_used >= TOKEN_LIMIT:
            yield f"data: {json.dumps({'bot': bot_name, 'error': f'Token limit reached ({tokens_used}/{TOKEN_LIMIT})'})}\n\n"
            return
        
        # Approximate token counting
        system_tokens = count_tokens(system)
        user_tokens = count_tokens(full_user_prompt)
        
        if tokens_used + system_tokens + user_tokens > TOKEN_LIMIT:
            yield f"data: {json.dumps({'bot': bot_name, 'error': 'Prompt too long - would exceed token limit'})}\n\n"
            return
        
        tokens_used += system_tokens + user_tokens
        
        payload = {
            "model": "deepseek/deepseek-chat-v3.1:free",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": full_user_prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 1500,
            "stream": True
        }
        
        headers = {
            "Authorization": f"Bearer {KEY}",
            "HTTP-Referer": request.host_url,
            "X-Title": "Pentad-Chat",
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            json=payload,
            headers=headers,
            stream=True,
            timeout=60
        )
        
        if response.status_code != 200:
            error_msg = f"API error: {response.status_code} - {response.text}"
            logger.error(f"OpenRouter API error for {bot_name}: {error_msg}")
            yield f"data: {json.dumps({'bot': bot_name, 'error': error_msg})}\n\n"
            return
        
        bot_tokens = 0
        full_response = ""
        
        for line in response.iter_lines():
            if line:
                line = line.decode('utf-8')
                if line.startswith('data: '):
                    data = line[6:]
                    if data == '[DONE]':
                        break
                    try:
                        chunk_data = json.loads(data)
                        if 'choices' in chunk_data and chunk_data['choices']:
                            delta = chunk_data['choices'][0].get('delta', {})
                            if 'content' in delta:
                                content = delta['content']
                                full_response += content
                                bot_tokens += count_tokens(content)
                                yield f"data: {json.dumps({'bot': bot_name, 'text': content})}\n\n"
                    except json.JSONDecodeError:
                        continue
        
        tokens_used += bot_tokens
        yield f"data: {json.dumps({'bot': bot_name, 'done': True, 'tokens': tokens_used})}\n\n"
        
    except Exception as exc:
        logger.error(f"Generation error for {bot_name}: {str(exc)}")
        error_msg = f"Failed to generate response: {str(exc)}"
        yield f"data: {json.dumps({'bot': bot_name, 'error': error_msg})}\n\n"

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    try:
        data = request.json or {}
        prompt = data.get("prompt", "").strip()
        fileUrls = data.get("fileUrls", [])
        
        if not prompt and not fileUrls:
            return jsonify(error="Empty prompt and no files provided"), 400
        
        if tokens_used >= TOKEN_LIMIT:
            return jsonify(error=f"Token limit reached ({tokens_used}/{TOKEN_LIMIT})"), 429
        
        file_contents = []
        if fileUrls:
            for file_url in fileUrls:
                file_contents.append(f"File attached: {file_url}")

        def event_stream():
            generators = {}
            for key in MODELS.keys():
                generators[key] = generate(key, SYSTEM_PROMPTS[key], prompt, file_contents)
            
            active_bots = list(MODELS.keys())
            
            while active_bots:
                for bot_name in active_bots[:]:
                    try:
                        chunk = next(generators[bot_name])
                        yield chunk
                        
                        try:
                            chunk_data = json.loads(chunk.split('data: ')[1])
                            if chunk_data.get('done') or chunk_data.get('error'):
                                active_bots.remove(bot_name)
                        except:
                            pass
                            
                    except StopIteration:
                        active_bots.remove(bot_name)
                    except Exception as e:
                        logger.error(f"Stream error for {bot_name}: {str(e)}")
                        active_bots.remove(bot_name)
            
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

@app.route("/asklurk", methods=["POST"])
@login_required
def asklurk():
    try:
        data = request.json or {}
        answers = data.get("answers", {})
        prompt = data.get("prompt", "")
        
        if not answers:
            return jsonify(best="", error="No responses to analyze"), 400
        
        if not KEY:
            return jsonify(best="", error="OpenRouter API key not configured"), 500
        
        # Check token limit
        if tokens_used >= TOKEN_LIMIT:
            return jsonify(best="", error=f"Token limit reached ({tokens_used}/{TOKEN_LIMIT})"), 429
        
        try:
            merged_content = f"Original question: {prompt}\n\n"
            for key, response in answers.items():
                if key in MODELS:
                    merged_content += f"## {MODELS[key]['name']}:\n{response}\n\n"
            
            payload = {
                "model": "deepseek/deepseek-chat-v3.1:free",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are AskLurk - an expert AI synthesizer. Your task is to analyze responses from Logic AI, Creative AI, Technical AI, Philosophical AI, and Humorous AI to create the single best answer. Combine the logical reasoning, creative insights, technical accuracy, philosophical depth, and humorous engagement to provide a comprehensive, well-structured response that leverages the strengths of all approaches. Structure your response to be insightful, engaging, and balanced."
                    },
                    {
                        "role": "user",
                        "content": f"Please analyze these AI responses to the question: \"{prompt}\"\n\nHere are the responses:\n{merged_content}\n\nPlease provide the best synthesized answer that leverages the strengths of all AI responses:"
                    }
                ],
                "temperature": 0.3,
                "max_tokens": 1500,
            }
            
            headers = {
                "Authorization": f"Bearer {KEY}",
                "HTTP-Referer": request.host_url,
                "X-Title": "Pentad-Chat",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code != 200:
                raise Exception(f"API error: {response.status_code} - {response.text}")
            
            result = response.json()
            best_answer = result['choices'][0]['message']['content']
            asklurk_tokens = count_tokens(best_answer)
            global tokens_used
            tokens_used += asklurk_tokens
            
            return jsonify(best=best_answer, tokens_used=tokens_used)
            
        except Exception as e:
            logger.error(f"AskLurk error: {str(e)}")
            if answers:
                first_response = next(iter(answers.values()))
                return jsonify(best=f"Fallback - Using first response:\n\n{first_response}", error="AI synthesis failed")
            return jsonify(best="", error="No responses available for synthesis")
        
    except Exception as e:
        logger.error(f"AskLurk error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    """File upload endpoint - simplified for Vercel"""
    try:
        if 'files' not in request.files:
            return jsonify(urls=[], error="No files provided"), 400
        
        files = request.files.getlist('files')
        urls = []
        
        for file in files:
            if file.filename == '':
                continue
            
            # In Vercel, we can't save files permanently, so we return mock URLs
            name = f"{uuid.uuid4().hex}_{file.filename}"
            urls.append(f"/static/uploads/{name}")
        
        return jsonify(urls=urls)
    
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': 'File upload not available in demo'}), 500

@app.route("/tokens", methods=["GET"])
@login_required
def get_tokens():
    return jsonify({
        "tokens_used": tokens_used,
        "token_limit": TOKEN_LIMIT,
        "remaining_tokens": TOKEN_LIMIT - tokens_used,
        "usage_percentage": (tokens_used / TOKEN_LIMIT) * 100
    })

@app.route("/reset-tokens", methods=["POST"])
@login_required
def reset_tokens():
    global tokens_used
    tokens_used = 0
    return jsonify({"message": "Token counter reset", "tokens_used": tokens_used})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "api_key_configured": bool(KEY),
        "models_configured": len(MODELS),
        "tokens_used": tokens_used,
        "oauth_configured": bool(app.config.get("GOOGLE_CLIENT_ID") and app.config.get("GOOGLE_CLIENT_SECRET")),
        "user_count": 1 if session.get('user') else 0
    })

@app.errorhandler(401)
def unauthorized_error(error):
    return jsonify(error="Authentication required"), 401

@app.errorhandler(500)
def internal_error(error):
    return jsonify(error="Internal server error"), 500

# Vercel compatibility
def create_app():
    return app

# For local development
if __name__ == '__main__':
    # Check if we're in development mode
    if os.environ.get('FLASK_ENV') == 'development':
        app.config['SESSION_COOKIE_SECURE'] = False
        app.config['OAUTH2_REFRESH_TOKEN_GENERATOR'] = True
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
