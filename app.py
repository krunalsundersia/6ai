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

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error rendering index: {e}")
        return f"Error loading application: {str(e)}", 500

@app.route('/profile')
def profile():
    """User profile page"""
    try:
        return jsonify({
            "status": "success",
            "message": "No authentication required"
        })
    except Exception as e:
        logger.error(f"Error getting profile: {e}")
        return jsonify({"error": "Failed to get profile"}), 500

@app.route('/test-api')
def test_api():
    return jsonify({
        "status": "success",
        "message": "API is working"
    })

# Health check endpoint
@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "flask_working": True,
        "openrouter_configured": bool(OPENROUTER_API_KEY)
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    logger.info("Starting Flask application...")
    logger.info(f"OpenRouter API Key: {'✓ Configured' if OPENROUTER_API_KEY else '✗ Missing'}")
    logger.info(f"Server running on http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
