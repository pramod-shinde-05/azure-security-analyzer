from flask import Blueprint, render_template, Response

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Renders the main upload & template selection interface."""
    return render_template('index.html')

@main_bp.route('/sw.js')
def service_worker():
    """Unregisters any stale development service worker previously registered on 127.0.0.1."""
    content = "self.addEventListener('install', () => self.skipWaiting()); self.addEventListener('activate', () => self.registration.unregister());"
    return Response(content, mimetype='application/javascript')


