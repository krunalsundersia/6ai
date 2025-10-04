import os
import json
import logging
from flask import Flask, request, Response, jsonify, session
from flask_cors import CORS
import requests
from authlib.integrations.flask_client import OAuth

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration for Vercel
app.config.update(
    SECRET_KEY=os.environ.get("SESSION_SECRET", "vercel-secret-key-" + os.urandom(24).hex()),
    GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID"),
    GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET"),
)

# Vercel-specific session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_DOMAIN=None,  # Important for Vercel
)

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
        client_kwargs={
            'scope': 'openid email profile',
        },
    )
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

@app.route('/')
def index():
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
            
        redirect_uri = request.host_url + 'api/login/google/authorize'
        return oauth.google.authorize_redirect(redirect_uri)
        
    except Exception as e:
        logger.error(f"Google login error: {str(e)}")
        return jsonify(error="Authentication error"), 500

@app.route('/api/login/google/authorize')
def google_authorize():
    try:
        token = oauth.google.authorize_access_token()
        if not token:
            return jsonify(error="Failed to get access token"), 400
            
        resp = oauth.google.get('userinfo')
        user_info = resp.json()
        
        if not user_info.get('email'):
            return jsonify(error="Email not provided"), 400
            
        session['user'] = {
            'name': user_info.get('name', ''),
            'email': user_info.get('email'),
            'picture': user_info.get('picture', ''),
            'provider': 'google'
        }
        
        # Redirect to frontend
        frontend_url = os.environ.get('FRONTEND_URL', request.host_url)
        return redirect(frontend_url)
    
    except Exception as e:
        logger.error(f"Google auth error: {str(e)}")
        return jsonify(error="Authentication failed"), 400

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
        
        if tokens_used >= TOKEN_LIMIT:
            yield f"data: {json.dumps({'bot': bot_name, 'error': f'Token limit reached ({tokens_used}/{TOKEN_LIMIT})'})}\n\n"
            return
        
        system_tokens = count_tokens(system)
        user_tokens = count_tokens(full_user_prompt)
        
        if tokens_used + system_tokens + user_tokens > TOKEN_LIMIT:
            yield f"data: {json.dumps({'bot': bot_name, 'error': 'Prompt too long'})}\n\n"
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
            error_msg = f"API error: {response.status_code}"
            yield f"data: {json.dumps({'bot': bot_name, 'error': error_msg})}\n\n"
            return
        
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
                                yield f"data: {json.dumps({'bot': bot_name, 'text': content})}\n\n"
                    except json.JSONDecodeError:
                        continue
        
        yield f"data: {json.dumps({'bot': bot_name, 'done': True})}\n\n"
        
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
        
        if tokens_used >= TOKEN_LIMIT:
            return jsonify(error=f"Token limit reached ({tokens_used}/{TOKEN_LIMIT})"), 429

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
        
        data = request.json or {}
        answers = data.get("answers", {})
        prompt = data.get("prompt", "")
        
        if not answers:
            return jsonify(best="", error="No responses to analyze"), 400
        
        if not KEY:
            return jsonify(best="", error="OpenRouter API key not configured"), 500
        
        if tokens_used >= TOKEN_LIMIT:
            return jsonify(best="", error=f"Token limit reached ({tokens_used}/{TOKEN_LIMIT})"), 429
        
        merged_content = f"Original question: {prompt}\n\n"
        for key, response in answers.items():
            if key in MODELS:
                merged_content += f"## {MODELS[key]['name']}:\n{response}\n\n"
        
        payload = {
            "model": "deepseek/deepseek-chat-v3.1:free",
            "messages": [
                {
                    "role": "system",
                    "content": "You are AskLurk - an expert AI synthesizer. Create the best answer by combining strengths from all AI responses."
                },
                {
                    "role": "user",
                    "content": f"Question: {prompt}\n\nResponses:\n{merged_content}\n\nSynthesized answer:"
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
            raise Exception(f"API error: {response.status_code}")
        
        result = response.json()
        best_answer = result['choices'][0]['message']['content']
        
        return jsonify(best=best_answer)
        
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

# Vercel serverless handler
def create_app():
    return app

if __name__ == '__main__':
    app.run(debug=True)
