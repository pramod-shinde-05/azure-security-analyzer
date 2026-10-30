import os
import sys
from pathlib import Path
from flask import Flask, render_template, request, send_from_directory

# Ensure the root package directory is always on sys.path
package_root = str(Path(__file__).resolve().parent.parent)
if package_root not in sys.path:
    sys.path.insert(0, package_root)

from config import config_by_name

def create_app(config_name=None):
    """Application factory for Azure Security Analyzer."""
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')

    current_dir = Path(__file__).resolve().parent
    static_dir = current_dir / 'static'
    template_dir = current_dir / 'templates'

    app = Flask(
        __name__,
        static_folder=str(static_dir),
        template_folder=str(template_dir),
        static_url_path='/static'
    )
    app.config.from_object(config_by_name[config_name])

    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Register blueprints
    from app.routes.main import main_bp
    from app.routes.upload import upload_bp
    from app.routes.analysis import analysis_bp
    from app.routes.ai_analysis import ai_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(ai_bp)

    # Explicit static route fallback to guarantee correct MIME types
    @app.route('/static/<path:filename>')
    def serve_static(filename):
        return send_from_directory(str(static_dir), filename)

    # Error handlers
    @app.errorhandler(413)
    def request_entity_too_large(error):
        return render_template(
            'index.html',
            error_message="Uploaded file exceeds the maximum allowed file size limit (10 MB)."
        ), 413

    @app.errorhandler(404)
    def page_not_found(error):
        # Don't serve HTML on missing static assets or API endpoints
        if request.path.startswith('/static/') or request.path.startswith('/api/'):
            return ("Asset or endpoint not found", 404, {'Content-Type': 'text/plain'})
        return render_template('index.html', error_message="The requested page or analysis session was not found."), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template('index.html', error_message="An unexpected server error occurred during processing."), 500

    return app
