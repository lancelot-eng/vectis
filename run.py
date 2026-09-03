from app import create_app

app = create_app()

if __name__ == '__main__':
    # En local uniquement. En production, Render utilise Gunicorn (voir Procfile).
    app.run(debug=True, host='0.0.0.0', port=5000)
