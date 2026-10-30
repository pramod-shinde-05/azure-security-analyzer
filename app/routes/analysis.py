import os
import json
from pathlib import Path
from flask import Blueprint, render_template, jsonify, abort, current_app, Response, redirect, url_for, flash
from app.utils.sanitization import get_storage_path, generate_secure_storage_id
from app.services.template_parser import ArmTemplateParser
from app.services.resource_mapper import ResourceMapper
from app.services.security_scanner import SecurityScanner
from app.services.report_generator import ReportGenerator

analysis_bp = Blueprint('analysis', __name__)

def _load_and_analyze(file_id: str):
    """Internal helper to load template, parse, scan, map graph, and generate report."""
    upload_dir = current_app.config['UPLOAD_FOLDER']
    try:
        file_path = get_storage_path(upload_dir, file_id)
    except ValueError:
        return None

    if not file_path.exists():
        return None

    # Load metadata if exists
    meta_path = Path(upload_dir) / f"{file_id}.meta.json"
    filename = "template.json"
    upload_time = ""
    meta_warnings = []
    if meta_path.exists():
        try:
            with open(meta_path, 'r', encoding='utf-8') as mf:
                meta = json.load(mf)
                filename = meta.get("original_filename", filename)
                upload_time = meta.get("upload_timestamp", "")
                meta_warnings = meta.get("validation_warnings", [])
        except Exception:
            pass

    # Read template content
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            template_data = json.load(f)
    except Exception:
        return None

    # 1. Parse ARM template
    parser = ArmTemplateParser(template_data)
    resources, metadata, parse_warnings = parser.parse()
    all_warnings = meta_warnings + parse_warnings

    # 2. Run deterministic security rules
    scanner = SecurityScanner()
    findings = scanner.scan(resources, metadata)

    # 3. Build Cytoscape graph
    mapper = ResourceMapper(resources, findings)
    graph_data = mapper.generate_graph()

    # 4. Generate report summary
    reporter = ReportGenerator(
        file_id=file_id,
        filename=filename,
        resources=resources,
        edges=graph_data["edges"],
        findings=findings,
        metadata=metadata,
        warnings=all_warnings
    )
    summary = reporter.generate_summary()
    export_data = reporter.generate_export_report()

    return {
        "file_id": file_id,
        "filename": filename,
        "upload_time": upload_time,
        "summary": summary,
        "graph": graph_data,
        "findings": [f.to_dict() for f in findings],
        "resources": [
            {
                "id": r.id,
                "name": r.name,
                "type": r.type,
                "category": r.category,
                "location": r.location,
                "api_version": r.api_version,
                "depends_on": r.depends_on,
                "json_path": r.json_path,
                "properties": r.properties
            }
            for r in resources
        ],
        "export_data": export_data,
        "warnings": all_warnings
    }

@analysis_bp.route('/analysis/<file_id>')
def view_analysis(file_id: str):
    """Renders the interactive visualizer and security dashboard."""
    analysis_data = _load_and_analyze(file_id)
    if not analysis_data:
        flash(f"Analysis session '{file_id}' not found or expired.", "error")
        return redirect(url_for('main.index'))

    return render_template(
        'dashboard.html',
        file_id=file_id,
        filename=analysis_data["filename"],
        summary=analysis_data["summary"],
        initial_data_json=json.dumps({
            "graph": analysis_data["graph"],
            "findings": analysis_data["findings"],
            "resources": analysis_data["resources"],
            "summary": analysis_data["summary"],
            "warnings": analysis_data["warnings"]
        })
    )

@analysis_bp.route('/api/analysis/<file_id>')
def get_analysis_data(file_id: str):
    """API endpoint providing the graph and findings JSON payload."""
    analysis_data = _load_and_analyze(file_id)
    if not analysis_data:
        return jsonify({"error": "Template analysis not found"}), 404

    return jsonify({
        "success": True,
        "file_id": file_id,
        "filename": analysis_data["filename"],
        "summary": analysis_data["summary"],
        "graph": analysis_data["graph"],
        "findings": analysis_data["findings"],
        "resources": analysis_data["resources"],
        "warnings": analysis_data["warnings"]
    })

@analysis_bp.route('/report/<file_id>/export')
def export_report(file_id: str):
    """Exports the complete audit report as a downloadable JSON file."""
    analysis_data = _load_and_analyze(file_id)
    if not analysis_data:
        abort(404, description="Template analysis not found")

    report_json = json.dumps(analysis_data["export_data"], indent=2)
    response = Response(report_json, mimetype='application/json')
    response.headers['Content-Disposition'] = f'attachment; filename=security-report-{file_id[:8]}.json'
    return response

@analysis_bp.route('/api/load-sample/<sample_name>', methods=['POST'])
def load_sample(sample_name: str):
    """Quickly loads a pre-packaged sample template for immediate demonstration."""
    sample_files = {
        "secure": "secure_template.json",
        "insecure": "insecure_template.json",
        "complex": "complex_template.json"
    }

    if sample_name not in sample_files:
        return jsonify({"success": False, "error": f"Unknown sample '{sample_name}'"}), 400

    base_dir = Path(__file__).resolve().parent.parent.parent
    sample_path = base_dir / "tests" / "fixtures" / sample_files[sample_name]

    if not sample_path.exists():
        return jsonify({"success": False, "error": f"Sample fixture file not found: {sample_files[sample_name]}"}), 404

    with open(sample_path, 'r', encoding='utf-8') as f:
        content_str = f.read()

    upload_dir = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    file_id = generate_secure_storage_id()
    dest_path = get_storage_path(upload_dir, file_id)

    with open(dest_path, 'w', encoding='utf-8') as f:
        f.write(content_str)

    meta_path = Path(upload_dir) / f"{file_id}.meta.json"
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump({
            "file_id": file_id,
            "original_filename": f"sample_{sample_name}.json",
            "upload_timestamp": "sample-demo",
            "validation_status": "VALID",
            "validation_warnings": []
        }, f, indent=2)

    return jsonify({
        "success": True,
        "file_id": file_id,
        "redirect_url": url_for('analysis.view_analysis', file_id=file_id)
    })

