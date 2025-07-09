import os
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
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,  # 500MB file size limit
    PREFERRED_URL_SCHEME='https',  # For secure URL generation
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
    video_url = db.Column(db.String(200), nullable=False)
    video_title = db.Column(db.String(200), nullable=False)
    download_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    format_type = db.Column(db.String(20), nullable=False, default='mp4')

# Initialize database
with app.app_context():
    try:
        db.create_all()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
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

@app.route('/download', methods=['POST'])
def download():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    url = request.form.get('url', '').strip()
    format_type = request.form.get('format', 'mp4').lower()

    if not url:
        return jsonify({'error': 'YouTube URL is required'}), 400

    try:
        # Validate URL format
        if 'youtube.com/watch?v=' not in url and 'youtu.be/' not in url:
            return jsonify({'error': 'Invalid YouTube URL format'}), 400

        # Enhanced yt-dlp configuration
        ydl_opts = {
            'outtmpl': os.path.join(app.config['DOWNLOAD_FOLDER'], '%(title)s.%(ext)s'),
            'quiet': False,
            'no_warnings': False,
            'ignoreerrors': False,
            'retries': 3,
            'fragment_retries': 3,
            'extract_flat': False,
            'skip_unavailable_fragments': False,
            'ratelimit': 1000000,
            'throttledratelimit': 500000,
            'cookiefile': os.path.join(app.instance_path, 'cookies.txt') if os.path.exists(os.path.join(app.instance_path, 'cookies.txt')) else None,
            'referer': 'https://www.youtube.com/',
            'user_agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
            ]),
            'extractor_args': {
                'youtube': {
                    'skip': ['dash', 'hls'],
                    'player_client': ['android', 'web']
                }
            },
            'postprocessor_args': {
                'ffmpeg': ['-hide_banner', '-loglevel', 'error']
            },
            'socket_timeout': 30,
            'extractor_retries': 3,
            'noplaylist': True,
            'proxy': os.environ.get('HTTPS_PROXY', ''),
            'source_address': '0.0.0.0',
            'http_headers': {
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            }
        }

        # Format configuration
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

        logger.info(f"Attempting download: {url}")

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            # First check video availability
            info = ydl.extract_info(url, download=False)
            
            if not info:
                logger.error(f"Failed to extract info for URL: {url}")
                return jsonify({'error': 'Could not retrieve video information'}), 400
            
            if info.get('availability') == 'unavailable':
                logger.warning(f"Video unavailable: {url}")
                return jsonify({'error': 'Video is unavailable (private, deleted, or restricted)'}), 403
            
            # Proceed with download
            ydl.download([url])
            filename = ydl.prepare_filename(info)

            if format_type == 'mp3':
                filename = os.path.splitext(filename)[0] + '.mp3'

            video_title = info.get('title', 'Untitled Video')

            # Record download history
            history = DownloadHistory(
                user_id=session['user_id'],
                video_url=url,
                video_title=video_title,
                format_type=format_type
            )
            db.session.add(history)
            db.session.commit()

            logger.info(f"Successfully downloaded: {video_title}")
            return jsonify({
                'filename': os.path.basename(filename),
                'title': video_title,
                'download_url': url_for('download_file', filename=os.path.basename(filename), _external=True)
            })

    except yt_dlp.utils.DownloadError as e:
        error_msg = str(e)
        logger.error(f"Download failed: {error_msg}")
        
        if 'Sign in to confirm' in error_msg:
            return jsonify({
                'error': 'YouTube requires verification. Please add your YouTube cookies to the app.',
                'solution': 'Create a cookies.txt file in the instance folder with your YouTube login cookies'
            }), 403
        elif 'unavailable' in error_msg.lower():
            return jsonify({'error': 'Video is not available for download'}), 403
        elif 'private' in error_msg.lower():
            return jsonify({'error': 'Private videos cannot be downloaded'}), 403
        elif 'age restricted' in error_msg.lower():
            return jsonify({'error': 'Age-restricted content (try adding cookies)'}), 403
        elif '403' in error_msg:
            return jsonify({'error': 'YouTube blocked the request (try VPN or later)'}), 403
        else:
            return jsonify({'error': f'Download failed: {error_msg}'}), 500
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Unexpected error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
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
        return redirect(url_for('login'))
    
    try:
        # Security check - prevent directory traversal
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

@app.route('/health')
def health_check():
    try:
        # Check database connection
        db.session.execute(text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'download_folder': os.path.exists(app.config['DOWNLOAD_FOLDER']),
            'database': 'connected',
            'environment': os.environ.get('FLASK_ENV', 'development')
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=app.config['DEBUG'],
        threaded=True
    )
