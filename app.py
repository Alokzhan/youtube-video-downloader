import os
import re
import random
import logging
import traceback
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import yt_dlp
from flask_migrate import Migrate
from sqlalchemy import text

# Initialize Flask app
app = Flask(__name__)

# Enhanced configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key-' + os.urandom(16).hex()),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///database.db').replace('postgres://', 'postgresql://', 1),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    DEBUG=os.environ.get('FLASK_ENV') == 'development',
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,
    PREFERRED_URL_SCHEME='https',
    YOUTUBE_COOKIE_PATH=os.path.join('instance', 'cookies.txt')
)

# Configure download folder
app.config['DOWNLOAD_FOLDER'] = os.path.join(os.getcwd(), 'downloads')
os.makedirs(app.config['DOWNLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    downloads = db.relationship('DownloadHistory', backref='user', lazy=True, cascade='all, delete-orphan')

class DownloadHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    video_url = db.Column(db.String(500), nullable=False)
    video_title = db.Column(db.String(200), nullable=False)
    download_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    format_type = db.Column(db.String(20), nullable=False, default='mp4')
    status = db.Column(db.String(20), nullable=False, default='success')

# Initialize database
with app.app_context():
    try:
        db.create_all()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

def validate_youtube_url(url):
    """Validate and normalize YouTube URLs with strict video ID validation"""
    patterns = [
        r'(https?://)?(www\.)?youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})',
        r'(https?://)?youtu\.be/([a-zA-Z0-9_-]{11})',
        r'(https?://)?(www\.)?youtube\.com/shorts/([a-zA-Z0-9_-]{11})'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            video_id = match.group(3) if 'watch' in pattern or 'shorts' in pattern else match.group(2)
            return f"https://www.youtube.com/watch?v={video_id}"
    
    # Handle URLs with additional parameters
    base_pattern = r'(https?://)?(www\.)?(youtu\.be/|youtube\.com/watch\?v=)([a-zA-Z0-9_-]{11})'
    match = re.search(base_pattern, url.split('&')[0].split('?')[0])
    if match:
        return f"https://www.youtube.com/watch?v={match.group(4)}"
    
    return None

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'), code=302)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            if not username or not password:
                return render_template('login.html', error='Username and password required')
            
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session.permanent = True
                return redirect(url_for('index'))
            
            return render_template('login.html', error='Invalid credentials')
        
        return render_template('login.html')
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return render_template('login.html', error='An error occurred during login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            if not username or not password:
                return render_template('register.html', error='Username and password required')
            if len(username) < 4 or len(password) < 6:
                return render_template('register.html', error='Username (min 4 chars) and password (min 6 chars) required')
            
            if User.query.filter_by(username=username).first():
                return render_template('register.html', error='Username already exists')
            
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        
        return render_template('register.html')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}")
        return render_template('register.html', error='An error occurred during registration')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

def get_ytdl_options():
    """Generate dynamic yt-dlp options with cookie handling"""
    cookie_path = app.config['YOUTUBE_COOKIE_PATH']
    cookie_exists = os.path.exists(cookie_path)
    
    options = {
        'outtmpl': os.path.join(app.config['DOWNLOAD_FOLDER'], '%(title)s.%(ext)s'),
        'quiet': False,
        'no_warnings': False,
        'retries': 3,
        'fragment_retries': 3,
        'socket_timeout': 30,
        'extractor_retries': 3,
        'noplaylist': True,
        'proxy': os.environ.get('HTTPS_PROXY', ''),
        'source_address': '0.0.0.0',
        'http_headers': {
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Origin': 'https://www.youtube.com',
            'Referer': 'https://www.youtube.com/'
        },
        'extractor_args': {
            'youtube': {
                'skip': ['dash', 'hls'],
                'player_client': ['android', 'web']
            }
        },
        'postprocessor_args': {
            'ffmpeg': ['-hide_banner', '-loglevel', 'error']
        }
    }
    
    if cookie_exists:
        options.update({
            'cookiefile': cookie_path,
            'verbose': True
        })
    else:
        options.update({
            'user_agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
            ])
        })
    
    return options

@app.route('/download', methods=['POST'])
def download():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    url = request.form.get('url', '').strip()
    format_type = request.form.get('format', 'mp4').lower()

    if not url:
        return jsonify({'error': 'YouTube URL is required'}), 400

    try:
        # Validate and normalize URL
        normalized_url = validate_youtube_url(url)
        if not normalized_url:
            return jsonify({
                'error': 'Invalid YouTube URL format',
                'details': 'URL must be in format: https://youtu.be/VIDEO_ID or https://www.youtube.com/watch?v=VIDEO_ID',
                'example': 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'
            }), 400

        # Extract and validate video ID
        video_id = None
        if 'v=' in normalized_url:
            video_id = normalized_url.split('v=')[1].split('&')[0]
        elif 'youtu.be/' in normalized_url:
            video_id = normalized_url.split('youtu.be/')[1].split('?')[0]
            
        if not video_id or len(video_id) != 11:
            return jsonify({
                'error': 'Invalid YouTube video ID',
                'details': 'YouTube video IDs must be exactly 11 characters long',
                'example': 'dQw4w9WgXcQ'
            }), 400

        # Initialize download history record
        history = DownloadHistory(
            user_id=session['user_id'],
            video_url=normalized_url,
            video_title='Pending',
            format_type=format_type,
            status='processing'
        )
        db.session.add(history)
        db.session.commit()

        # Configure download options
        ydl_opts = get_ytdl_options()
        
        # Format specific options
        if format_type == 'mp3':
            ydl_opts.update({
                'format': 'bestaudio/best',
                'postprocessors': [{
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': '192',
                }],
            })
        elif format_type == 'mp4':
            ydl_opts['format'] = 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best'
        else:
            ydl_opts['format'] = 'best'

        logger.info(f"Starting download: {normalized_url}")

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            # First check video availability
            info = ydl.extract_info(normalized_url, download=False)
            
            if not info:
                raise ValueError('Could not retrieve video information')
            
            if info.get('availability') == 'unavailable':
                raise ValueError('Video is unavailable (private, deleted, or restricted)')
            
            # Update history with actual title
            history.video_title = info.get('title', 'Untitled Video')
            db.session.commit()

            # Proceed with download
            ydl.download([normalized_url])
            filename = ydl.prepare_filename(info)

            if format_type == 'mp3':
                filename = os.path.splitext(filename)[0] + '.mp3'

            logger.info(f"Download completed: {filename}")
            return jsonify({
                'filename': os.path.basename(filename),
                'title': history.video_title,
                'download_url': url_for('download_file', filename=os.path.basename(filename), _external=True)
            })

    except yt_dlp.utils.DownloadError as e:
        error_msg = str(e)
        logger.error(f"Download failed: {error_msg}")
        
        # Update history with error status
        if history:
            history.status = 'failed'
            db.session.commit()
        
        if 'Sign in to confirm' in error_msg:
            return jsonify({
                'error': 'YouTube requires verification',
                'solution': 'Add YouTube cookies to instance/cookies.txt',
                'cookie_required': True
            }), 403
        elif any(x in error_msg.lower() for x in ['unavailable', 'private', 'age restricted']):
            return jsonify({'error': 'Video is not available for download'}), 403
        elif '403' in error_msg or 'blocked' in error_msg.lower():
            return jsonify({'error': 'YouTube blocked the request (try VPN or later)'}), 403
        else:
            return jsonify({'error': f'Download failed: {error_msg}'}), 500
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Unexpected error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'error': 'Download failed',
            'details': str(e),
            'solution': 'Please check the URL and try again. If the problem persists, contact support.'
        }), 500

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'), code=302)
    
    try:
        downloads = DownloadHistory.query.filter_by(
            user_id=session['user_id']
        ).order_by(
            DownloadHistory.download_time.desc()
        ).all()
        
        return render_template('history.html', history=downloads)
    except Exception as e:
        logger.error(f"History error: {str(e)}")
        return render_template('history.html', error='Could not load download history')

@app.route('/downloads/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'), code=302)
    
    try:
        safe_filename = os.path.basename(filename)
        if not safe_filename or safe_filename != filename:
            return jsonify({'error': 'Invalid filename'}), 400

        file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], safe_filename)
        
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {safe_filename}")
            return jsonify({'error': 'File not available (may have expired)'}), 404
            
        return send_from_directory(
            app.config['DOWNLOAD_FOLDER'],
            safe_filename,
            as_attachment=True,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        logger.error(f"File download failed: {str(e)}")
        return jsonify({'error': 'Could not download file'}), 500

@app.route('/check_cookies')
def check_cookies():
    """Endpoint to verify cookies.txt status"""
    cookie_path = app.config['YOUTUBE_COOKIE_PATH']
    exists = os.path.exists(cookie_path)
    valid = exists and os.path.getsize(cookie_path) > 100
    
    return jsonify({
        'exists': exists,
        'valid': valid,
        'path': cookie_path
    })

@app.route('/health')
def health_check():
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'services': {
                'database': True,
                'storage': os.path.exists(app.config['DOWNLOAD_FOLDER']),
                'cookies': os.path.exists(app.config['YOUTUBE_COOKIE_PATH'])
            }
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=app.config['DEBUG'],
        threaded=True
    )
