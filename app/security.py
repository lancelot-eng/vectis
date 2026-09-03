from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Limite les tentatives par adresse IP : protège contre le bruteforce
# sur la connexion et contre le spam de créations de comptes.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=['200 per day', '50 per hour'],
    storage_uri='memory://',  # OK pour un seul serveur ; passer à Redis si scaling multi-instances
)
