La version utilisée de Python est :
  Python 3.12.4

Superset:

Pour activer environnement virtuel de superset : 
    venv_superset python -m venv_superset
    >> venv_superset\Scripts\activate

Installer Superset et ses dépendances:
     pip install apache-superset

Initialiser la base de données Superset :
     superset db upgrade

Créer un utilisateur admin :
   superset fab create-admin \
   --username Hanane \
   --firstname Hanane \
   --lastname Ijeoui \
   --email hanane@example.com \
   --password admin@2024

Ensuite Spécifie la config personnalisée :
    $env:SUPERSET_CONFIG_PATH = "chemin de fichier de config de superset"
    >>  $env:FLASK_APP = "superset.app"

Après lance superset:
  superset run -p 8088


Pour lancer app dans un aure terminal:
Activer env venv_app:
 venv_app python -m venv_app
 >> venv_app\Scripts\activate

Lancer app:
 python app.py
