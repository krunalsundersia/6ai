import os
import json
import logging
import sys
import uuid
from flask import Flask, request, Response, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv
from openai import OpenAI
import tiktoken
from io import BytesIO

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "your-secret-key-here")
CORS(app)

# Initialize token encoding
enc = tiktoken.get_encoding("cl100k_base")

# Initialize OpenRouter API key
KEY = os.getenv("OPENROUTER_API_KEY")
if not KEY:
    logging.error("OPENROUTER_API_KEY missing – export it or add to .env")
    sys.exit(1)

# Define the 5 AI models with their personalities
MODELS = {
    "logic": {"name": "Logic AI", "description": "analytical, structured, step-by-step"},
    "creative": {"name": "Creative AI", "description": "poetic, metaphorical, emotional"},
    "technical": {"name": "Technical AI", "description": "precise, technical, detail-oriented"},
    "philosophical": {"name": "Philosophical AI", "description": "deep, reflective, abstract"},
    "humorous": {"name": "Humorous AI", "description": "witty, lighthearted, engaging"}
}

# System prompts for each model
SYSTEM_PROMPTS = {
    "logic": "You are Logic AI — analytical, structured, step-by-step. Provide clear, logical reasoning and systematic approaches. Break down complex problems into manageable steps and explain your reasoning clearly.",
    "creative": "You are Creative AI — poetic, metaphorical, emotional. Use imaginative language and creative perspectives. Think outside the box and provide innovative solutions with vivid descriptions.",
    "technical": "You are Technical AI — precise, technical, detail-oriented. Provide accurate, detailed, and technically sound responses, focusing on facts, specifications, and practical applications.",
    "philosophical": "You are Philosophical AI — deep, reflective, abstract. Offer profound insights, explore existential questions, and provide thoughtful, nuanced perspectives.",
    "humorous": "You are Humorous AI — witty, lighthearted, engaging. Deliver responses with humor, clever analogies, and a playful tone while remaining relevant and informative."
}

# OpenRouter models to use
OPENROUTER_MODELS = {
    "logic": "deepseek/deepseek-chat-v3.1:free",
    "creative": "deepseek/deepseek-chat-v3.1:free",
    "technical": "deepseek/deepseek-chat-v3.1:free",
    "philosophical": "deepseek/deepseek-chat-v3.1:free",
    "humorous": "deepseek/deepseek-chat-v3.1:free",
    "asklurk": "deepseek/deepseek-chat-v3.1:free"
}

# Create uploads directory
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def extract_text_from_pdf(file_content):
    """Extract text content from PDF file"""
    try:
        pdf_file = BytesIO(file_content)
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text.strip()
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {str(e)}")
        return None


def generate(bot_name: str, system: str, user: str, file_contents: list = None):
    """Generate AI response for a specific bot using OpenRouter"""
    client = None
    try:
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=KEY,
            timeout=60.0  # Increased timeout for file processing
        )
        
        # Add file contents to the user prompt if available
        full_user_prompt = user
        if file_contents:
            file_context = "\n\n".join(file_contents)
            full_user_prompt = f"{user}\n\nAttached files content:\n{file_context}"
        
        model = OPENROUTER_MODELS.get(bot_name, "deepseek/deepseek-chat-v3.1:free")
        logger.info(f"Generating response for {bot_name} using model {model}")
        
        stream = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "http://localhost:5000",
                "X-Title": "Pentad-Chat"
            },
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": full_user_prompt}
            ],
            temperature=0.7,
            max_tokens=1500,  # Increased for file context
            stream=True,
        )
        
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content is not None:
                delta = chunk.choices[0].delta.content
                yield f"data: {json.dumps({'bot': bot_name, 'text': delta})}\n\n"
            
            if chunk.choices and chunk.choices[0].finish_reason:
                break
        
        logger.info(f"Completed generation for {bot_name}")
        yield f"data: {json.dumps({'bot': bot_name, 'done': True})}\n\n"
        
    except Exception as exc:
        logger.error(f"Error generating response for {bot_name}: {str(exc)}")
        error_msg = str(exc)
        if "401" in error_msg:
            error_msg = "Authentication failed. Invalid OpenRouter API key."
        elif "429" in error_msg:
            error_msg = "Rate limit exceeded. Please try again later."
        elif "404" in error_msg:
            error_msg = "Model not found or unavailable."
        else:
            error_msg = f"Failed to generate response: {error_msg}"
            
        yield f"data: {json.dumps({'bot': bot_name, 'error': error_msg})}\n\n"
    finally:
        if client:
            try:
                client.close()
            except:
                pass

@app.route("/asklurk", methods=["POST"])
def asklurk():
    """Synthesize the best answer from all AI responses"""
    try:
        data = request.json or {}
        answers = data.get("answers", {})
        prompt = data.get("prompt", "")
        
        if not answers:
            return jsonify(best="", error="No responses to analyze"), 400
        
        try:
            client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=KEY,
                timeout=30.0
            )
            
            merged_content = f"Original question: {prompt}\n\n"
            for key, response in answers.items():
                if key in MODELS:
                    merged_content += f"## {MODELS[key]['name']}:\n{response}\n\n"
            
            response = client.chat.completions.create(
                extra_headers={
                    "HTTP-Referer": "http://localhost:5000",
                    "X-Title": "Pentad-Chat"
                },
                model=OPENROUTER_MODELS["asklurk"],
                messages=[
                    {
                        "role": "system",
                        "content": """You are AskLurk - an expert AI synthesizer. Your task is to analyze responses from Logic AI, Creative AI, Technical AI, Philosophical AI, and Humorous AI to create the single best answer. 
                        
                        Combine the logical reasoning, creative insights, technical accuracy, philosophical depth, and humorous engagement to provide a comprehensive, well-structured response that leverages the strengths of all approaches.
                        
                        Structure your response to be insightful, engaging, and balanced."""
                    },
                    {
                        "role": "user",
                        "content": f"""Please analyze these AI responses to the question: "{prompt}"

Here are the responses:
{merged_content}

Please provide the best synthesized answer that combines the strengths of all AI responses:"""
                    }
                ],
                temperature=0.3,
                max_tokens=1500,
            )
            
            best_answer = response.choices[0].message.content
            
            return jsonify(best=best_answer)
            
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
def upload():
    """Handle file uploads"""
    try:
        if 'files' not in request.files:
            return jsonify(urls=[], error="No files provided"), 400
        
        files = request.files.getlist('files')
        urls = []
        
        for file in files:
            if file.filename == '':
                continue
            
            allowed_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.txt', '.doc', '.docx'}
            ext = os.path.splitext(file.filename)[1].lower()
            
            if ext not in allowed_extensions:
                continue
                
            name = f"{uuid.uuid4().hex}{ext}"
            path = os.path.join(UPLOAD_FOLDER, name)
            
            try:
                file.save(path)
                urls.append(f"/static/uploads/{name}")
            except Exception as e:
                logger.error(f"Error saving file {file.filename}: {str(e)}")
        
        return jsonify(urls=urls)
    
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "api_key_configured": bool(KEY),
        "models_configured": len(OPENROUTER_MODELS)
    })

@app.route("/chat", methods=["POST"])
def chat():
    """Main chat endpoint for all AI models"""
    try:
        data = request.json or {}
        prompt = data.get("prompt", "").strip()
        fileUrls = data.get("fileUrls", [])
        
        if not prompt and not fileUrls:
            return jsonify(error="Empty prompt and no files provided"), 400
        
        # Process uploaded files
        file_contents = []
        if fileUrls:
            for file_url in fileUrls:
                try:
                    file_path = file_url.replace('/static/uploads/', '')
                    full_path = os.path.join(UPLOAD_FOLDER, file_path)
                    
                    if os.path.exists(full_path):
                        with open(full_path, 'rb') as f:
                            file_content = f.read()
                        
                        filename = file_path.lower()
                        if filename.endswith('.pdf'):
                            text_content = extract_text_from_pdf(file_content)
                            if text_content:
                                file_contents.append(f"PDF Content from '{file_path}':\n{text_content}\n")
                        elif filename.endswith('.txt'):
                            text_content = file_content.decode('utf-8')
                            file_contents.append(f"Text Content from '{file_path}':\n{text_content}\n")
                        else:
                            file_contents.append(f"File '{file_path}'")
                            
                except Exception as e:
                    logger.error(f"Error processing file {file_url}: {str(e)}")
                    file_contents.append(f"File '{file_url}' (error processing)")

        def event_stream():
            generators = {}
            for key in MODELS.keys():
                generators[key] = generate(key, SYSTEM_PROMPTS[key], prompt, file_contents)
            
            active_bots = list(MODELS.keys())
            completed_bots = set()
            
            while active_bots:
                for bot_name in active_bots[:]:
                    try:
                        chunk = next(generators[bot_name])
                        yield chunk
                        
                        try:
                            chunk_data = json.loads(chunk.split('data: ')[1])
                            if chunk_data.get('done') or chunk_data.get('error'):
                                completed_bots.add(bot_name)
                                active_bots.remove(bot_name)
                        except:
                            pass
                            
                    except StopIteration:
                        completed_bots.add(bot_name)
                        active_bots.remove(bot_name)
                    
                    except Exception as e:
                        logger.error(f"Error streaming for {bot_name}: {str(e)}")
                        completed_bots.add(bot_name)
                        active_bots.remove(bot_name)
            
            yield f"data: {json.dumps({'all_done': True})}\n\n"

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    print("Starting Pentad Chat Server...")
    print(f"OpenRouter API Key: {'✓ Configured' if KEY else '✗ Missing'}")
    print("Available models: Logic AI, Creative AI, Technical AI, Philosophical AI, Humorous AI, AskLurk")
    print(f"PDF Support: ✓ Enabled with PyPDF2")
    print(f"Server running on http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)

