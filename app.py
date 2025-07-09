from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import yt_dlp
import os
import random
from datetime import datetime
from flask_migrate import Migrate

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db').replace('postgres://', 'postgresql://')
app.config['DOWNLOAD_FOLDER'] = os.path.join(app.instance_path, 'downloads')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = os.environ.get('FLASK_ENV') == 'development'

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class DownloadHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_url = db.Column(db.String(200), nullable=False)
    video_title = db.Column(db.String(200), nullable=False)
    download_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    format_type = db.Column(db.String(20), nullable=False, default='mp4')

# Initialize database
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username exists')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/download', methods=['POST'])
def download():
    if 'user_id' not in session:
        return jsonify({'error': 'Please log in'}), 401

    url = request.form.get('url')
    format_type = request.form.get('format', 'mp4')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]

        ydl_opts = {
            'outtmpl': os.path.join(app.config['DOWNLOAD_FOLDER'], '%(title)s.%(ext)s'),
            'quiet': True,
            'referer': 'https://www.youtube.com/',
            'user-agent': random.choice(user_agents),
            'retries': 10,
            'fragment_retries': 10,
            'extract_flat': False,
            'ignoreerrors': False,
            'skip_unavailable_fragments': False,
            'ratelimit': 1000000,
            'throttledratelimit': 500000,
        }

        if format_type == 'mp3':
            ydl_opts.update({
                'format': 'bestaudio/best',
                'postprocessors': [{
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': '192',
                }],
            })
        elif format_type == 'best':
            ydl_opts['format'] = 'bestvideo+bestaudio/best'
        elif format_type == 'mp4':
            ydl_opts['format'] = 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best'
        else:
            ydl_opts['format'] = 'bestvideo[ext=webm]+bestaudio[ext=webm]/best[ext=webm]/best'

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            filename = ydl.prepare_filename(info)

            if format_type == 'mp3':
                filename = os.path.splitext(filename)[0] + '.mp3'

            video_title = info.get('title', 'Unknown Title')

            history = DownloadHistory(
                user_id=session['user_id'],
                video_url=url,
                video_title=video_title,
                format_type=format_type
            )
            db.session.add(history)
            db.session.commit()

            return jsonify({
                'filename': os.path.basename(filename),
                'title': video_title
            })
    except yt_dlp.utils.DownloadError as e:
        if 'HTTP Error 403' in str(e):
            return jsonify({
                'error': 'YouTube is blocking downloads. Try again later or use a VPN.',
                'details': str(e)
            }), 403
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    history = DownloadHistory.query.filter_by(user_id=session['user_id']).order_by(
        DownloadHistory.download_time.desc()).all()
    return render_template('history.html', history=history)

@app.route('/download_file/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    try:
        return send_from_directory(
            app.config['DOWNLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)