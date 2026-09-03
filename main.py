from flask import Blueprint, render_template, current_app

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    return render_template('index.html', turnstile_site_key=current_app.config.get('TURNSTILE_SITE_KEY', ''))
