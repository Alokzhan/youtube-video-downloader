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
from functools import wraps
from werkzeug.utils import secure_filename
import uuid

# Initialize Flask app
app = Flask(__name__)

# Enhanced configuration with environment variables
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(32).hex()),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///database.db').replace('postgres://', 'postgresql://', 1),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    DEBUG=os.environ.get('FLASK_ENV', 'production') == 'development',
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,  # 500MB limit
    PREFERRED_URL_SCHEME='https',
    YOUTUBE_COOKIE_PATH=os.path.join('instance', 'cookies.txt'),
    DOWNLOAD_FOLDER=os.path.join(os.getcwd(), 'downloads'),
    MAX_DOWNLOADS_PER_USER=50,  # Limit downloads per user
    DOWNLOAD_EXPIRY_DAYS=7,  # Days before downloads are cleaned up
    RATE_LIMIT=os.environ.get('RATE_LIMIT', '100 per day'),  # Rate limiting
)

# Configure download folder
os.makedirs(app.config['DOWNLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.dirname(app.config['YOUTUBE_COOKIE_PATH']), exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    downloads = db.relationship('DownloadHistory', backref='user', lazy=True, cascade='all, delete-orphan')

class DownloadHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    video_url = db.Column(db.String(500), nullable=False)
    video_title = db.Column(db.String(200), nullable=False)
    download_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    format_type = db.Column(db.String(20), nullable=False, default='mp4')
    status = db.Column(db.String(20), nullable=False, default='processing')
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)  # in bytes
    expiry_date = db.Column(db.DateTime)

# Initialize database
with app.app_context():
    try:
        db.create_all()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        traceback.print_exc()
        raise

# Helper functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def validate_youtube_url(url):
    """Validate and normalize YouTube URLs with strict video ID validation"""
    patterns = [
        r'(https?://)?(www\.)?youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})',
        r'(https?://)?youtu\.be/([a-zA-Z0-9_-]{11})',
        r'(https?://)?(www\.)?youtube\.com/shorts/([a-zA-Z0-9_-]{11})',
        r'(https?://)?(www\.)?youtube\.com/embed/([a-zA-Z0-9_-]{11})',
        r'(https?://)?(www\.)?youtube\.com/v/([a-zA-Z0-9_-]{11})'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            video_id = match.group(3) if 'watch' in pattern or 'shorts' in pattern or 'embed' in pattern or 'v' in pattern else match.group(2)
            return f"https://www.youtube.com/watch?v={video_id}"
    
    # Handle URLs with additional parameters
    base_pattern = r'(https?://)?(www\.)?(youtu\.be/|youtube\.com/(watch\?v=|shorts/|embed/|v/))([a-zA-Z0-9_-]{11})'
    match = re.search(base_pattern, url.split('&')[0].split('?')[0])
    if match:
        return f"https://www.youtube.com/watch?v={match.group(5)}"
    
    return None

def sanitize_filename(filename):
    """Sanitize filename to prevent directory traversal and other security issues"""
    filename = secure_filename(filename)
    # Add random string to prevent guessing
    return f"{uuid.uuid4().hex[:8]}_{filename}"

def get_ytdl_options():
    """Generate dynamic yt-dlp options with cookie handling"""
    cookie_path = app.config['YOUTUBE_COOKIE_PATH']
    cookie_exists = os.path.exists(cookie_path)
    
    options = {
        'outtmpl': os.path.join(app.config['DOWNLOAD_FOLDER'], '%(id)s_%(title)s.%(ext)s'),
        'quiet': True,
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
            'Referer': 'https://www.youtube.com/',
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
            ])
        },
        'extractor_args': {
            'youtube': {
                'skip': ['dash', 'hls'],
                'player_client': ['android', 'web']
            }
        },
        'postprocessor_args': {
            'ffmpeg': ['-hide_banner', '-loglevel', 'error']
        },
        'concurrent_fragment_downloads': 4,
        'throttledratelimit': 1000000,  # 1MB/s limit
    }
    
    if cookie_exists:
        options.update({
            'cookiefile': cookie_path,
            'verbose': False
        })
    
    return options

def cleanup_old_downloads():
    """Clean up old downloads and database records"""
    try:
        expiry_threshold = datetime.utcnow() - timedelta(days=app.config['DOWNLOAD_EXPIRY_DAYS'])
        
        # Get expired downloads
        expired_downloads = DownloadHistory.query.filter(
            DownloadHistory.expiry_date <= datetime.utcnow()
        ).all()
        
        for download in expired_downloads:
            try:
                if download.file_path and os.path.exists(download.file_path):
                    os.remove(download.file_path)
                db.session.delete(download)
            except Exception as e:
                logger.error(f"Failed to cleanup download {download.id}: {str(e)}")
                continue
        
        db.session.commit()
        logger.info(f"Cleaned up {len(expired_downloads)} expired downloads")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Cleanup error: {str(e)}")

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            next_url = request.form.get('next', url_for('index'))
            
            if not username or not password:
                return render_template('login.html', error='Username and password required')
            
            user = User.query.filter_by(username=username, is_active=True).first()
            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session.permanent = True
                user.last_login = datetime.utcnow()
                db.session.commit()
                return redirect(next_url)
            
            return render_template('login.html', error='Invalid credentials', next=next_url)
        
        return render_template('login.html', next=request.args.get('next', url_for('index')))
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return render_template('login.html', error='An error occurred during login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            
            if not username or not password:
                return render_template('register.html', error='Username and password required')
            if len(username) < 4 or len(password) < 8:
                return render_template('register.html', error='Username (min 4 chars) and password (min 8 chars) required')
            if password != confirm_password:
                return render_template('register.html', error='Passwords do not match')
            
            if User.query.filter_by(username=username).first():
                return render_template('register.html', error='Username already exists')
            
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            
            # Auto-login after registration
            session['user_id'] = new_user.id
            session.permanent = True
            return redirect(url_for('index'))
        
        return render_template('register.html')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}")
        return render_template('register.html', error='An error occurred during registration')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/download', methods=['POST'])
@login_required
def download():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    # Check download limit
    user_downloads = DownloadHistory.query.filter_by(user_id=session['user_id']).count()
    if user_downloads >= app.config['MAX_DOWNLOADS_PER_USER']:
        return jsonify({'error': 'Download limit reached'}), 429

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

        # Extract video ID
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
        expiry_date = datetime.utcnow() + timedelta(days=app.config['DOWNLOAD_EXPIRY_DAYS'])
        history = DownloadHistory(
            user_id=session['user_id'],
            video_url=normalized_url,
            video_title='Pending',
            format_type=format_type,
            status='processing',
            expiry_date=expiry_date
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
            
            # Check video duration (max 2 hours)
            if info.get('duration', 0) > 7200:  # 2 hours in seconds
                raise ValueError('Video is too long (maximum 2 hours allowed)')
            
            # Update history with actual title
            history.video_title = info.get('title', 'Untitled Video')
            db.session.commit()

            # Proceed with download
            ydl.download([normalized_url])
            filename = ydl.prepare_filename(info)

            if format_type == 'mp3':
                filename = os.path.splitext(filename)[0] + '.mp3'

            # Update history with file info
            history.file_path = filename
            history.file_size = os.path.getsize(filename)
            history.status = 'success'
            db.session.commit()

            logger.info(f"Download completed: {filename}")
            return jsonify({
                'filename': os.path.basename(filename),
                'title': history.video_title,
                'download_url': url_for('download_file', filename=os.path.basename(filename), _external=True),
                'size': history.file_size
            })

    except yt_dlp.utils.DownloadError as e:
        error_msg = str(e)
        logger.error(f"Download failed: {error_msg}")
        
        # Update history with error status
        if 'history' in locals():
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
@login_required
def history():
    try:
        downloads = DownloadHistory.query.filter_by(
            user_id=session['user_id']
        ).order_by(
            DownloadHistory.download_time.desc()
        ).limit(100).all()
        
        return render_template('history.html', history=downloads)
    except Exception as e:
        logger.error(f"History error: {str(e)}")
        return render_template('history.html', error='Could not load download history')

@app.route('/downloads/<filename>')
@login_required
def download_file(filename):
    try:
        safe_filename = os.path.basename(filename)
        if not safe_filename or safe_filename != filename:
            return jsonify({'error': 'Invalid filename'}), 400

        file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], safe_filename)
        
        # Verify the file belongs to the user
        download = DownloadHistory.query.filter_by(
            user_id=session['user_id'],
            file_path=file_path
        ).first()
        
        if not download:
            return jsonify({'error': 'File not found in your history'}), 404
            
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {safe_filename}")
            return jsonify({'error': 'File not available (may have expired)'}), 404
            
        return send_from_directory(
            app.config['DOWNLOAD_FOLDER'],
            safe_filename,
            as_attachment=True,
            mimetype='application/octet-stream',
            download_name=f"{download.video_title}.{download.format_type}"
        )
    except Exception as e:
        logger.error(f"File download failed: {str(e)}")
        return jsonify({'error': 'Could not download file'}), 500

@app.route('/profile')
@login_required
def profile():
    try:
        user = User.query.get(session['user_id'])
        download_count = DownloadHistory.query.filter_by(user_id=session['user_id']).count()
        return render_template('profile.html', user=user, download_count=download_count)
    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/check_cookies')
@login_required
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
        
        # Check storage space
        total, used, free = 0, 0, 0
        try:
            stat = os.statvfs(app.config['DOWNLOAD_FOLDER'])
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bfree * stat.f_frsize
            used = total - free
        except:
            pass
        
        return jsonify({
            'status': 'healthy',
            'services': {
                'database': True,
                'storage': {
                    'available': os.path.exists(app.config['DOWNLOAD_FOLDER']),
                    'total': total,
                    'used': used,
                    'free': free
                },
                'cookies': os.path.exists(app.config['YOUTUBE_COOKIE_PATH'])
            }
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# Scheduled cleanup
@app.before_request
def before_request():
    # Run cleanup on first request each day
    if random.random() < 0.01:  # 1% chance to run cleanup on any request
        cleanup_old_downloads()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=app.config['DEBUG'],
        threaded=True
    )
