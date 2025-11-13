import os
from cachelib.file import FileSystemCache

# Génère une clé secrète aléatoire (remplace par ta propre clé si tu veux la garder fixe)
SECRET_KEY = "MY_SECRET_KEY"

# Configuration du cache
CACHE_CONFIG = {
    "CACHE_TYPE": "FileSystemCache",
    "CACHE_DIR": os.path.join(os.getcwd(), "superset_home", "cache"),
}

# Base de données locale pour Superset
SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(os.getcwd(), "superset_home", "superset.db")

# Activer le mode debug (optionnel)
DEBUG = True
