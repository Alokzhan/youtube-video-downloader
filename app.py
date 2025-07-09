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

app = Flask(__name__)

# Configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key-' + os.urandom(16).hex()),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///database.db').replace('postgres://', 'postgresql://', 1),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    DEBUG=os.environ.get('FLASK_ENV') == 'development',
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,
    DOWNLOAD_FOLDER=os.path.join(os.getcwd(), 'downloads'),
    YOUTUBE_COOKIE_PATH=os.path.join('instance', 'cookies.txt'),
    PREFERRED_URL_SCHEME='https'
)

# Ensure download folder exists
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
    status = db.Column(db.String(20), default='processing')

# Initialize database
with app.app_context():
    db.create_all()

def validate_youtube_url(url):
    """Validate and normalize YouTube URLs"""
    patterns = [
        r'(https?://)?(www\.)?youtube\.com/watch\?v=([^&]+)',
        r'(https?://)?youtu\.be/([^?]+)',
        r'(https?://)?(www\.)?youtube\.com/shorts/([^?]+)'
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return f"https://www.youtube.com/watch?v={match.group(3) if 'watch' in pattern else match.group(2)}"
    return None

def get_ytdl_options():
    """Generate yt-dlp options with cookie handling"""
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

    # Add cookies if available
    if os.path.exists(app.config['YOUTUBE_COOKIE_PATH']):
        options.update({
            'cookiefile': app.config['YOUTUBE_COOKIE_PATH'],
            'verbose': True
        })
    else:
        options['user_agent'] = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
        ])
    
    return options

@app.route('/download', methods=['POST'])
def download():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    url = request.form.get('url', '').strip()
    format_type = request.form.get('format', 'mp4').lower()

    if not url:
        return jsonify({'error': 'YouTube URL is required'}), 400

    # Validate and normalize URL
    video_url = validate_youtube_url(url)
    if not video_url:
        return jsonify({'error': 'Invalid YouTube URL format'}), 400

    try:
        # Create download record
        history = DownloadHistory(
            user_id=session['user_id'],
            video_url=video_url,
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

        logger.info(f"Starting download: {video_url}")

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            # Check video info first
            info = ydl.extract_info(video_url, download=False)
            
            if not info:
                raise ValueError('Could not retrieve video information')
            
            if info.get('availability') == 'unavailable':
                raise ValueError('Video is unavailable (private, deleted, or restricted)')

            # Update with actual title
            history.video_title = info.get('title', 'Untitled Video')
            db.session.commit()

            # Download the video
            ydl.download([video_url])
            filename = ydl.prepare_filename(info)

            if format_type == 'mp3':
                filename = os.path.splitext(filename)[0] + '.mp3'

            # Update status
            history.status = 'success'
            db.session.commit()

            return jsonify({
                'filename': os.path.basename(filename),
                'title': history.video_title,
                'download_url': url_for('download_file', filename=os.path.basename(filename), _external=True)
            })

    except yt_dlp.utils.DownloadError as e:
        error_msg = str(e)
        logger.error(f"Download failed: {error_msg}")
        
        # Update status
        if 'history' in locals():
            history.status = 'failed'
            db.session.commit()
        
        if 'Sign in to confirm' in error_msg:
            return jsonify({
                'error': 'YouTube requires verification',
                'solution': 'Add your YouTube cookies to instance/cookies.txt',
                'cookie_required': True
            }), 403
        elif any(x in error_msg.lower() for x in ['unavailable', 'private', 'age restricted']):
            return jsonify({'error': 'Video is not available for download'}), 403
        elif '403' in error_msg:
            return jsonify({'error': 'YouTube blocked the request (try VPN or later)'}), 403
        else:
            return jsonify({'error': f'Download failed: {error_msg}'}), 500
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Unexpected error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500

# ... [keep all other routes the same as in previous version] ...

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=app.config['DEBUG'],
        threaded=True
    )
