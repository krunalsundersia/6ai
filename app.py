import os
import json
import logging
import sys
import uuid
import base64
import tempfile
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
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
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
    import fitz  # PyMuPDF for PDF processing
    import magic  # For file type detection
    
except ImportError as e:
    logger.error(f"Missing dependency: {e}")
except Exception as e:
    logger.error(f"Error initializing dependencies: {e}")

# Initialize OpenAI client for OpenRouter
client = None
if OPENROUTER_API_KEY:
    try:
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=OPENROUTER_API_KEY,
        )
        logger.info("OpenAI client initialized successfully for OpenRouter")
    except Exception as e:
        logger.error(f"Failed to initialize OpenAI client: {e}")

def login_required(f):
    """Decorator to check if user is authenticated"""
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is in session
        if 'user' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def extract_text_from_pdf(file_content):
    """Extract text from PDF file using PyMuPDF"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
            temp_file.write(file_content)
            temp_file.flush()
            
            doc = fitz.open(temp_file.name)
            text = ""
            for page in doc:
                text += page.get_text()
            doc.close()
            
            # Clean up temporary file
            os.unlink(temp_file.name)
            
            return text.strip()
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {e}")
        return None

def extract_text_from_image(file_content):
    """Extract text from image using OCR"""
    try:
        # You can integrate with OCR services like Tesseract here
        # For now, return a placeholder
        logger.info("Image OCR processing would go here")
        return "Image content detected (OCR processing required)"
    except Exception as e:
        logger.error(f"Error processing image: {e}")
        return None

def process_uploaded_file(file_content, filename):
    """Process uploaded file and extract text content"""
    try:
        # Detect file type
        file_type = magic.from_buffer(file_content, mime=True)
        logger.info(f"Processing file: {filename}, type: {file_type}")
        
        if file_type == 'application/pdf':
            return extract_text_from_pdf(file_content)
        elif file_type.startswith('image/'):
            return extract_text_from_image(file_content)
        elif file_type.startswith('text/'):
            return file_content.decode('utf-8')
        else:
            # Try to decode as text for other file types
            try:
                return file_content.decode('utf-8')
            except:
                return f"Binary file detected: {filename}"
                
    except Exception as e:
        logger.error(f"Error processing file {filename}: {e}")
        return None

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    """Handle chat messages with optional file uploads"""
    try:
        data = request.get_json()
        message = data.get('message', '')
        file_data = data.get('file', None)
        file_name = data.get('fileName', '')
        
        if not message and not file_data:
            return jsonify({"error": "No message or file provided"}), 400
        
        # Process file if provided
        file_content_text = ""
        if file_data and file_name:
            try:
                # Decode base64 file data
                file_content = base64.b64decode(file_data.split(',')[1] if ',' in file_data else file_data)
                file_content_text = process_uploaded_file(file_content, file_name)
                
                if file_content_text:
                    message += f"\n\nFile content from {file_name}:\n{file_content_text}"
                else:
                    message += f"\n\nUnable to process file: {file_name}"
                    
            except Exception as e:
                logger.error(f"Error processing file in chat: {e}")
                message += f"\n\nError processing file: {file_name}"
        
        if not client:
            # Mock response if OpenRouter is not configured
            return jsonify({
                "response": f"Received your message: {message[:100]}... (OpenRouter not configured)",
                "file_processed": bool(file_content_text)
            })
        
        # Call OpenRouter API
        try:
            completion = client.chat.completions.create(
                extra_headers={
                    "HTTP-Referer": request.host_url,
                    "X-Title": "AI Chat App",
                },
                model="openai/gpt-3.5-turbo",
                messages=[
                    {
                        "role": "user",
                        "content": message
                    }
                ]
            )
            
            response_text = completion.choices[0].message.content
            
            return jsonify({
                "response": response_text,
                "file_processed": bool(file_content_text)
            })
            
        except Exception as e:
            logger.error(f"Error calling OpenRouter API: {e}")
            return jsonify({
                "error": "Failed to get response from AI service",
                "file_processed": bool(file_content_text)
            }), 500
            
    except Exception as e:
        logger.error(f"Error in chat endpoint: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/upload-file', methods=['POST'])
@login_required
def upload_file():
    """Handle file upload and text extraction"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Read file content
        file_content = file.read()
        filename = file.filename
        
        # Process file and extract text
        extracted_text = process_uploaded_file(file_content, filename)
        
        if extracted_text:
            return jsonify({
                "success": True,
                "filename": filename,
                "content": extracted_text,
                "message": f"Successfully processed {filename}"
            })
        else:
            return jsonify({
                "error": f"Could not extract text from {filename}"
            }), 400
            
    except Exception as e:
        logger.error(f"Error in file upload: {e}")
        return jsonify({"error": "File upload failed"}), 500

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

@app.route('/auth/success', methods=['POST'])
def auth_success():
    """Handle successful Firebase authentication from frontend"""
    try:
        data = request.get_json()
        user_data = data.get('user', {})
        
        if not user_data:
            return jsonify({"error": "No user data provided"}), 400
        
        # Store user info in session (trusting the frontend for this demo)
        # In production, you should verify the Firebase token on backend
        session['user'] = {
            'id': user_data.get('uid', str(uuid.uuid4())),
            'email': user_data.get('email', ''),
            'name': user_data.get('displayName', 'User'),
            'photo_url': user_data.get('photoURL', ''),
            'authenticated': True
        }
        
        logger.info(f"User logged in: {session['user']['email']}")
        return jsonify({
            "status": "success",
            "message": "Authentication successful",
            "user": session['user']
        })
            
    except Exception as e:
        logger.error(f"Error in auth success: {e}")
        return jsonify({"error": "Authentication failed"}), 500

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
        "file_processing_available": 'fitz' in sys.modules,
        "user_authenticated": 'user' in session
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    logger.info("Starting Flask application...")
    logger.info(f"OpenRouter API Key: {'✓ Configured' if OPENROUTER_API_KEY else '✗ Missing'}")
    logger.info(f"PDF Processing: {'✓ Available' if 'fitz' in sys.modules else '✗ Not available'}")
    logger.info(f"File Type Detection: {'✓ Available' if 'magic' in sys.modules else '✗ Not available'}")
    logger.info(f"Server running on http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
