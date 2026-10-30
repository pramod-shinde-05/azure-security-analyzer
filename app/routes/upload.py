import os
import json
import datetime
from pathlib import Path
from flask import Blueprint, request, jsonify, redirect, url_for, flash, current_app
from werkzeug.utils import secure_filename
from app.utils.validation import allowed_file, validate_arm_content
from app.utils.sanitization import generate_secure_storage_id, get_storage_path

upload_bp = Blueprint('upload', __name__)

@upload_bp.route('/upload', methods=['POST'])
def upload_file():
    """Handles ARM template file upload and validation."""
    is_ajax = request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if 'template_file' not in request.files:
        if is_ajax:
            return jsonify({"success": False, "error": "No file field 'template_file' provided."}), 400
        flash("No file was selected for upload.", "error")
        return redirect(url_for('main.index'))

    file = request.files['template_file']

    if file.filename == '':
        if is_ajax:
            return jsonify({"success": False, "error": "No file selected."}), 400
        flash("No file was selected for upload.", "error")
        return redirect(url_for('main.index'))

    allowed_exts = current_app.config.get('ALLOWED_EXTENSIONS', {'json'})
    if not allowed_file(file.filename, allowed_exts):
        msg = f"Invalid file type '{file.filename}'. Only ARM JSON templates (.json) are permitted."
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "error")
        return redirect(url_for('main.index'))

    try:
        content_bytes = file.read()
        content_str = content_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        msg = f"Could not read uploaded file: {str(e)}"
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "error")
        return redirect(url_for('main.index'))

    # Validate ARM structure
    is_valid, status, parsed_data, warnings_or_errors = validate_arm_content(content_str)
    if not is_valid:
        error_msg = " | ".join(warnings_or_errors)
        if is_ajax:
            return jsonify({
                "success": False,
                "status": status,
                "error": error_msg,
                "details": warnings_or_errors
            }), 400
        flash(f"Template validation failed ({status}): {error_msg}", "error")
        return redirect(url_for('main.index'))

    # Store validated template securely
    upload_dir = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    file_id = generate_secure_storage_id()
    dest_path = get_storage_path(upload_dir, file_id)

    with open(dest_path, 'w', encoding='utf-8') as f:
        f.write(content_str)

    # Store metadata alongside
    meta_path = Path(upload_dir) / f"{file_id}.meta.json"
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump({
            "file_id": file_id,
            "original_filename": secure_filename(file.filename),
            "upload_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "validation_status": status,
            "validation_warnings": warnings_or_errors
        }, f, indent=2)

    redirect_target = url_for('analysis.view_analysis', file_id=file_id)
    if is_ajax:
        return jsonify({
            "success": True,
            "file_id": file_id,
            "status": status,
            "warnings": warnings_or_errors,
            "redirect_url": redirect_target
        })

    return redirect(redirect_target)

