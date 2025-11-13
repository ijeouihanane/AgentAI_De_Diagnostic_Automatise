# Agent AI de Diagnostic Automatisé

Application intelligente de détection et diagnostic automatisé des anomalies dans les données  
Développée en novembre 2025 avec **Python 3.12.4**, **Flask**, **Apache Superset**, **Pandas**, **Langchain**, **Llama3** et **Bootstrap 5**.

---

## Fonctionnalités

### Utilisateurs
- Téléverser des données (CSV, Excel)
- Détection automatique des anomalies
- Génération de rapports (PDF, PNG, Excel)
- Visualisation interactive des résultats

### Administrateurs (via Superset)
- Dashboard analytique en temps réel
- Filtres avancés par date, type d’anomalie, criticité
- Export des données analysées

---

## Technologies utilisées

| Technologie              | Version       |
|--------------------------|---------------|
| Python                   | 3.12.4        |
| Flask                    | 3.0+          |
| Apache Superset          | 4.0+          |
| Pandas / NumPy           | 2.2+ / 2.0+   |
| Llama                    | 3.2:3b        |
| Langchain                | 0.3.27        |
|matplotlib                |3.10.6         |
| Bootstrap                | 5.3           |
| PostgreSQL               |               |

---

## Prérequis

- **Python 3.12.4**
- Git
- PowerShell ou Terminal

---

## Captures d’écran

<div align="center">

## Page Login 
<img src="screenshots/Pagelogin.png" alt="Page login" width="800"/>

### Inscription
<img src="screenshots/SignUpInterface.png" alt="Page d'inscription" width="800"/>

### Page d'accueil
<img src="screenshots/HomePage.png" alt="Page d'accueil" width="800"/>

### Interface chatbot
<img src="screenshots/InterfaceAgent.png" alt="Interface du chatbot" width="800"/>

### Gestions des utilisateurs
<img src="screenshots/InterfaceUsersManagment.png" alt="Gestion des utilisateurs" width="800"/>

### Interface des paramètres Rule-Based
<img src="screenshots/InterfaceSettingsRule-based.png" alt=" Interface des paramètres Rule-Based" width="800"/>

### Histprique des rapports générés
<img src="screenshots/HistoryOfReportsPage.png" alt="Historique des rapports générés" width="800"/>

## HomePageAdmin
<img src="screenshots/HomePageAdmin.png" alt="Pagde d'accueil Admin" width="800"/>

## Rapport généré
<img src="screenshots/RapportGénéréPDF.png" alt="Rapport PDF généré" width="800"/>

</div>



---

## Installation & Lancement


# 1. Cloner le projet
git clone https://github.com/ijeouihanane/AgentAI_De_Diagnostic_Automatise.git
cd AgentAI_De_Diagnostic_Automatise

# 2. Créer et activer l’environnement Superset
python -m venv venv_superset
venv_superset\Scripts\activate
pip install apache-superset

# 3. Initialiser Superset
superset db upgrade
superset fab create-admin \
  --username X \
  --firstname X\
  --lastname X \
  --email X@example.com \
  --password admin@2024

# 4. Lancer Superset (dans un terminal)
$env:FLASK_APP = "superset"
superset run -p 8088 --with-threads --reload

# 5. Dans un autre terminal → Application Flask
python -m venv venv_app
venv_app\Scripts\activate
pip install -r requirements.txt
python app.py
