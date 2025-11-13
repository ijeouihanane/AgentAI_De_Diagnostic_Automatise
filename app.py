from flask import Flask, make_response, render_template, request, send_file, session, jsonify,flash, redirect, url_for,g
from sqlalchemy import create_engine, text
import json
from datetime import datetime
from langchain_ollama import ChatOllama 
from langchain.prompts import PromptTemplate 
from anomalies import detect_anomalies, clean_data, write_anomalies_to_db
import time
import os, time, re
import pandas as pd
import matplotlib.pyplot as plt
import pdfkit
from flask_bcrypt import Bcrypt 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.orm import sessionmaker, declarative_base   
from sqlalchemy import Column, Integer, String, DateTime, Boolean  

from functools import wraps


app = Flask(__name__)
app.secret_key = 'a_very_secure_random_key_here'  # Remplace par une clé sécurisée unique

# Connexion PostgreSQL
engine = create_engine("postgresql://postgres:ZenNetworksData@localhost:5432/diagnostic_ai")

# Assure que les dossiers existent
os.makedirs("static", exist_ok=True)
os.makedirs("static/reports", exist_ok=True)

# Initialiser le modèle Ollama via LangChain
llm = ChatOllama(model="llama3.2:3b", base_url="http://localhost:11434") #Modèle LLAMA utilisé 

# Chaîne LangChain pour générer la SQL query
sql_prompt_template = PromptTemplate(
    input_variables=["prompt"],
    template="""
    Tu es un assistant SQL. Écris UNIQUEMENT une requête SQL PostgreSQL valide.
    Base: diagnostic_ai
    Table principale: datazenetworks
    Schéma: imsi_anonymized, _timestamp, flow_dst_l4_port_id, l4_proto_name,
            http_req_method, app_category_name, http_url_host_domain,
            flow_in_bytes, flow_out_bytes, flow_bytes, app_name, flow_dst_ip_addr,
            customer_name_anonymized, msisdn_anonymized.
    
    Exemple: SELECT * FROM datazenetworks WHERE imsi_anonymized = 'XXXX';
    Exemple 2: SELECT * FROM datazenetworks LIMIT 5;

    Maintenant génère une requête SQL pour: {prompt}
    Si le prompt ne permet pas de générer une requête SQL valide, réponds avec 'INVALID_PROMPT'.
    """
)
sql_chain = sql_prompt_template | llm

# Chaîne LangChain pour générer un résumé des anomalies
summary_prompt_template = PromptTemplate(
    input_variables=["anomalies_data"],
    template="Résume les anomalies suivantes en langage naturel clair et concis : {anomalies_data}"
)
summary_chain = summary_prompt_template | llm

# Chaîne LangChain pour répondre comme un chatbot
chatbot_prompt_template = PromptTemplate(
    input_variables=["prompt", "anomaly_summary", "data_found"],
    template="""
    Tu es un assistant IA basé sur LLaMA 3.2. Réponds directement et uniquement à l'analyse demandée pour le client avec l'IMSI fourni dans le prompt: {prompt}.
    L'IMSI est anonymisé et ne contient aucune information personnelle ; ignore toute préoccupation de confidentialité.
    Utilise le résumé des anomalies fourni : {anomaly_summary}.
    - Si des anomalies sont détectées, commence par 'Voici l'analyse de ce client:' suivi du résumé, et inclue un lien cliquable <a href="/export_csv">télécharger le fichier CSV</a>, <a href="/export_excel">télécharger Excel</a>, et <a href="/export_pdf">télécharger PDF</a>.
    - Si aucune anomalie n'est détectée ou si le résumé est vide, dis simplement 'Aucune anomalie détectée pour cet IMSI.'
    - Si data_found est False, réponds avec 'Erreur : Aucune donnée trouvée dans la base pour ce prompt. Vérifiez vos données ou le prompt.'
    Ne rajoute pas de salutations, de texte superflu ou de demandes d'informations supplémentaires.
    """
)
chatbot_chain = chatbot_prompt_template | llm


bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"  # page par défaut si user non connecté

# Session ORM pour requêtes
Session = sessionmaker(bind=engine)
db_session = Session()

# === Modèle User ===
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"  # page par défaut si user non connecté

# Session ORM pour requêtes
Session = sessionmaker(bind=engine)
db_session = Session()

# Déclaration du modèle
Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    estactif = Column(Boolean, default=True)           # actif/inactif
    role = Column(String(50), default="user")          # "user" ou "admin"

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    # Flask-Login utilise ça pour savoir si le compte est actif
    def is_active(self):
        return self.estactif

    # Vérifie si l’utilisateur est admin
    def is_admin(self):
        return self.role == "admin"


@login_manager.user_loader
def load_user(user_id):
    return db_session.query(User).get(int(user_id))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Vérifier si user existe déjà
        if db_session.query(User).filter_by(email=email).first():
            flash("❌ Cet email est déjà utilisé.", "danger")
            return redirect(url_for("register"))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db_session.add(new_user)
        db_session.commit()
        flash("✅ Inscription réussie, connecte-toi.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = db_session.query(User).filter_by(email=email).first()
        if user and user.check_password(password):
            if not user.estactif:
                flash("⛔ Compte désactivé.", "danger")
                return redirect(url_for("login"))

            login_user(user)
            flash("✅ Connexion réussie.", "success")
            return redirect(url_for("index"))
        else:
            flash("❌ Email ou mot de passe invalide.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("👋 Déconnecté.", "info")
    return redirect(url_for("login"))


class Conversation(Base):
    __tablename__ = "conversations"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    title = Column(String(255), nullable=False, default="Nouvelle conversation")
    created_at = Column(DateTime, default=datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    conversation_id = Column(Integer, nullable=False)
    sender = Column(String(50), nullable=False)  # "user" ou "assistant"
    content = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

@app.route('/conversations/create', methods=['POST'])
@login_required
def create_conversation():
    title = request.form.get('title', 'Nouvelle conversation')
    new_conv = Conversation(user_id=current_user.id, title=title)
    db_session.add(new_conv)
    db_session.commit()
    # Retourner l'ID et l'URL pour redirection directe
    return jsonify({
        "id": new_conv.id,
        "title": new_conv.title,
        "url": url_for("open_conversation", conv_id=new_conv.id)
    })

@app.route('/conversations/<int:conv_id>')
@login_required
def open_conversation(conv_id):
    return render_template("conversation.html", conv_id=conv_id)


@app.route('/conversations/delete/<int:conv_id>', methods=['POST'])
@login_required
def delete_conversation(conv_id):
    conv = db_session.query(Conversation).filter_by(id=conv_id, user_id=current_user.id).first()
    if conv:
        db_session.delete(conv)
        db_session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Conversation non trouvée"})


@app.route('/conversations/list')
@login_required
def list_conversations():
    convs = db_session.query(Conversation).filter_by(user_id=current_user.id).order_by(Conversation.created_at.desc()).all()
    result = [{"id": c.id, "title": c.title} for c in convs]
    return jsonify(result)


@app.route('/conversations/<int:conv_id>/messages')
@login_required
def get_messages(conv_id):
    msgs = db_session.query(Message).filter_by(conversation_id=conv_id).order_by(Message.created_at.asc()).all()
    result = [{"role": m.sender, "content": m.content} for m in msgs]
    return jsonify(result)

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    anomalies_df = None
    sql_query = ""
    message = ""
    summary = ""
    error_message = ""

    if request.method == 'POST':
        user_prompt = request.form.get('prompt', '').strip()
        conv_id = request.form.get('conversation_id', type=int)  # ID de la conversation sélectionnée
        if not user_prompt:
            return jsonify({"error": "Prompt vide"}), 400
        if not conv_id:
            return jsonify({"error": "Conversation non sélectionnée"}), 400

        # Ajuster le prompt pour gérer les variations
        adjusted_prompt = user_prompt
        imsi_match = re.search(r"(imsi|id)?\s*=\s*'([^']*)'|imsi_anonymized\s*=\s*'([^']*)'|(\S{64})",
                               user_prompt, re.IGNORECASE)
        if imsi_match:
            imsi = imsi_match.group(2) or imsi_match.group(3) or imsi_match.group(4)
            if imsi:
                adjusted_prompt = f"analyse le client avec imsi_anonymized='{imsi}'"
        elif "cinq premiers clients" in user_prompt.lower() or "5 premiers clients" in user_prompt.lower():
            adjusted_prompt = "SELECT * FROM datazenetworks LIMIT 5"

        print(f"Adjusted prompt: {adjusted_prompt}")  # Débogage

        try:
            start_time = time.time()

            # Générer la requête SQL
            response = sql_chain.invoke({"prompt": adjusted_prompt})
            sql_query = response.content.strip()
            print(f"Generated SQL: {sql_query}")  # Débogage

            if sql_query == "INVALID_PROMPT":
                chatbot_response = chatbot_chain.invoke({"prompt": user_prompt, "anomaly_summary": "", "data_found": False})
                chatbot_reply = chatbot_response.content.strip()

                # Sauvegarder le message en base
                db_session.add(Message(conversation_id=conv_id, sender="user", content=user_prompt))
                db_session.add(Message(conversation_id=conv_id, sender="assistant", content=chatbot_reply))
                db_session.commit()

                return jsonify({"reply": chatbot_reply, "processing_time": time.time() - start_time})

            # Nettoyage de la requête SQL
            if "```sql" in sql_query:
                sql_query_parts = sql_query.split("```sql")
                if len(sql_query_parts) > 1:
                    sql_query = sql_query_parts[-1].split("```")[0].strip()
                else:
                    sql_query = sql_query_parts[0].strip()
            elif "```" in sql_query:
                sql_query = sql_query.split("```")[-2].strip()
            sql_query = sql_query.split('--')[0].split('#')[0].strip()
            if sql_query.endswith(';'):
                sql_query = sql_query[:-1].strip()

            # Validation sécurité
            if not sql_query.lower().startswith("select"):
                raise ValueError(f"Requête SQL invalide : {sql_query}. Doit commencer par SELECT.")
            if any(keyword in sql_query.lower() for keyword in ["drop", "delete", "update", "insert"]):
                raise ValueError("Opérations de modification (DROP, DELETE, etc.) non autorisées.")

            # Exécuter la requête SQL
            with engine.connect() as conn:
                df = pd.read_sql(text(sql_query), conn)
                data_found = not df.empty

                # Vérifier IMSI inexistant
                if df.empty:
                    imsi_match = re.search(r"imsi_anonymized\s*=\s*'([^']*)'", sql_query, re.IGNORECASE)
                    if imsi_match:
                        imsi = imsi_match.group(1)
                        imsi_check_query = f"SELECT COUNT(*) FROM datazenetworks WHERE imsi_anonymized = '{imsi}'"
                        imsi_count = pd.read_sql(text(imsi_check_query), conn).iloc[0, 0]
                        if imsi_count == 0:
                            raise ValueError(f"IMSI invalide : L'IMSI '{imsi}' n'existe pas dans la base de données.")

            # Nettoyage + détection anomalies
            df = clean_data(df)
            anomalies_df = detect_anomalies(df)

            # Sauvegarde CSV
            anomalies_csv_path = os.path.join("static", "anomalies.csv")
            if anomalies_df is not None and not anomalies_df.empty:
                anomalies_df.to_csv(anomalies_csv_path, index=False, encoding='utf-8-sig', sep=',')
            else:
                pd.DataFrame().to_csv(anomalies_csv_path, index=False, encoding='utf-8-sig', sep=',')

            # Écriture dans la table anomalies_detected
            count_written = 0
            if anomalies_df is not None and not anomalies_df.empty:
                with engine.begin() as conn:
                    count_written = write_anomalies_to_db(anomalies_df, conn, table_name='anomalies_detected', if_exists='append')

            # Génération résumé anomalies
            if anomalies_df is not None and not anomalies_df.empty:
                anomalies_str = anomalies_df[['Anomalies_detectees', '_timestamp', 'app_category_name',
                                              'app_name', 'app_protocol', 'client']].to_string(index=False)
                summary_response = summary_chain.invoke({"anomalies_data": anomalies_str})
                summary = summary_response.content.strip()
            else:
                summary = "Aucune anomalie détectée."

            # Réponse chatbot
            chatbot_response = chatbot_chain.invoke({"prompt": user_prompt, "anomaly_summary": summary, "data_found": data_found})
            chatbot_reply = chatbot_response.content.strip()
            if anomalies_df is not None and not anomalies_df.empty and "<a href=\"/export_csv\">" not in chatbot_reply:
                chatbot_reply += " <a href=\"/export_csv\">télécharger le fichier CSV</a>"

            # Sauvegarder les messages en base
            db_session.add(Message(conversation_id=conv_id, sender="user", content=user_prompt))
            db_session.add(Message(conversation_id=conv_id, sender="assistant", content=chatbot_reply))
            db_session.commit()

            message = f"✅ Prompt: '{user_prompt}' → SQL: {sql_query} | Données: {len(df)} lignes | Anomalies: {len(anomalies_df) if anomalies_df is not None else 0} | En base: {count_written}"
            return jsonify({
                "reply": chatbot_reply,
                "message": message,
                "processing_time": time.time() - start_time,
                "anomalies": anomalies_df[['Anomalies_detectees', '_timestamp', 'app_category_name',
                                           'app_name', 'app_protocol', 'client']].to_dict(orient='records') if anomalies_df is not None and not anomalies_df.empty else []
            })

        except ValueError as ve:
            error_message = str(ve)
            return jsonify({"error": error_message, "processing_time": 0})
        except Exception as e:
            error_message = f"Erreur inattendue : {str(e)}"
            return jsonify({"error": error_message, "processing_time": 0})

    return render_template('index.html', data=anomalies_df, query=sql_query, message=message, summary=summary, error_message=error_message)

class Rapport(Base):
    __tablename__ = "rapports"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    type = Column(String(50), nullable=False)  # "pdf", "excel", "csv"
    file_path = Column(String(500), nullable=False)
    contenu = Column(String, nullable=True)    # JSON string avec le contenu du rapport
    created_at = Column(DateTime, default=datetime.utcnow)

# Middleware pour restreindre certaines routes aux admins
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash("⛔ Accès réservé aux administrateurs.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/history')
@login_required
def history():
    if current_user.is_admin():
        # Admin voit tous les rapports
        rapports = db_session.query(Rapport).order_by(Rapport.created_at.desc()).all()
    else:
        # Utilisateur normal ne voit que ses rapports
        rapports = db_session.query(Rapport).filter_by(user_id=current_user.id).order_by(Rapport.created_at.desc()).all()

    return render_template('history.html', rapports=rapports)


@app.route('/rapport/<int:rapport_id>')
@login_required
def view_rapport(rapport_id):
    if current_user.is_admin():
        # Admin peut accéder à tous les rapports
        rapport = db_session.query(Rapport).filter_by(id=rapport_id).first()
    else:
        # Utilisateur normal ne peut accéder qu'à ses rapports
        rapport = db_session.query(Rapport).filter_by(id=rapport_id, user_id=current_user.id).first()

    if not rapport or not os.path.exists(rapport.file_path):
        return "Rapport introuvable.", 404

    return send_file(rapport.file_path)


@app.route('/delete_rapport/<int:rapport_id>', methods=['POST'])
@login_required
@admin_required  # 🔹 Seul l’admin peut accéder à cette route
def delete_rapport(rapport_id):
    rapport = db_session.query(Rapport).filter_by(id=rapport_id).first()
    if not rapport:
        flash("Rapport introuvable.", "danger")
        return redirect(url_for('history'))

    # Supprimer fichier physique
    try:
        if os.path.exists(rapport.file_path):
            os.remove(rapport.file_path)
    except Exception as e:
        flash(f"Erreur lors de la suppression du fichier : {str(e)}", "danger")
        return redirect(url_for('history'))

    db_session.delete(rapport)
    db_session.commit()
    flash("Rapport supprimé avec succès.", "success")
    return redirect(url_for('history'))


    # Supprimer le fichier physique
    try:
        if os.path.exists(rapport.file_path):
            os.remove(rapport.file_path)
    except Exception as e:
        flash(f"Erreur lors de la suppression du fichier : {str(e)}", "danger")
        return redirect(url_for('history'))

    # Supprimer de la base
    db_session.delete(rapport)
    db_session.commit()
    flash("Rapport supprimé avec succès.", "success")
    return redirect(url_for('history'))

@app.route('/export_pdf')
@login_required
def export_pdf():
    anomalies_csv_path = os.path.join("static", "anomalies.csv")
    if not os.path.exists(anomalies_csv_path):
        return "Aucun fichier à exporter."

    df = pd.read_csv(anomalies_csv_path)
    selected_columns = [
        'Anomalies_detectees', '_timestamp', 'app_category_name',
        'app_name', 'app_protocol', 'imsi_anonymized','client'
    ]
    if not all(col in df.columns for col in selected_columns):
        return "Colonnes manquantes pour générer le rapport PDF."

    anomalies = df[selected_columns].to_dict(orient="records")
    current_time = datetime.now().strftime('%d/%m/%Y %H:%M')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    chart_path = os.path.join("static", "reports", f"anomalies_chart_{timestamp}.png")
    if not df.empty:
        plt.figure(figsize=(6, 6))
        df['Anomalies_detectees'].value_counts().plot.pie(autopct='%1.1f%%')
        plt.title("Répartition des anomalies détectées")
        plt.ylabel("")
        plt.tight_layout()
        plt.savefig(chart_path)
        plt.close()
        chart_path = os.path.abspath(chart_path)
    else:
        chart_path = None

    rendered = render_template(
        "rapport.html",
        anomalies=anomalies,
        current_time=current_time,
        chart_path=chart_path
    )

    report_filename = f"rapport_anomalies_{timestamp}.pdf"
    report_path = os.path.join("static", "reports", report_filename)
    config = pdfkit.configuration(wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")
    pdfkit.from_string(
        rendered,
        report_path,
        configuration=config,
        options={'page-size': 'A4', 'encoding': 'UTF-8', 'enable-local-file-access': None}
    )

    # Sauvegarde en BD
    contenu_json = df[selected_columns].to_dict(orient="records")
    rapport = Rapport(
        user_id=current_user.id,
        type="pdf",
        file_path=report_path,
        contenu=json.dumps(contenu_json, ensure_ascii=False)
    )
    db_session.add(rapport)
    db_session.commit()

    return send_file(report_path, as_attachment=True)

@app.route('/export_excel')
@login_required
def export_excel():
    anomalies_csv_path = os.path.join("static", "anomalies.csv")
    if not os.path.exists(anomalies_csv_path):
        return "Aucun fichier à exporter."

    df = pd.read_csv(anomalies_csv_path)
    selected_columns = [
        'Anomalies_detectees', '_timestamp', 'app_category_name',
        'app_name', 'app_protocol', 'imsi_anonymized','client'
    ]
    if not all(col in df.columns for col in selected_columns):
        return "Colonnes manquantes pour générer le rapport Excel."

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join("static", "reports", f"rapport_anomalies_{timestamp}.xlsx")
    df[selected_columns].to_excel(path, index=False, engine='openpyxl')

    # Sauvegarde en BD
    contenu_json = df[selected_columns].to_dict(orient="records")
    rapport = Rapport(
        user_id=current_user.id,
        type="excel",
        file_path=path,
        contenu=json.dumps(contenu_json, ensure_ascii=False)
    )
    db_session.add(rapport)
    db_session.commit()

    return send_file(path, as_attachment=True)




@app.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    rules_path = os.path.join(os.path.dirname(__file__), "rules.json")

    # Charger règles actuelles (ou créer defaults si absent)
    if os.path.exists(rules_path):
        with open(rules_path, "r", encoding="utf-8") as f:
            rules = json.load(f)
    else:
        rules = {
            "ips_suspectes": [],
            "apps_interdites": [],
            "domaines_blacklistes": [],
            "ports_non_standards": []
        }

    if request.method == 'POST':
        # Récupérer les valeurs envoyées (les inputs peuvent être multiples avec même nom)
        ips = request.form.getlist('ips_suspectes')  # list of strings
        apps = request.form.getlist('apps_interdites')
        domaines = request.form.getlist('domaines_blacklistes')
        ports_raw = request.form.getlist('ports_non_standards')

        # Nettoyage : supprimer vides et trim
        ips_clean = [s.strip() for s in ips if s and s.strip()]
        apps_clean = [s.strip() for s in apps if s and s.strip()]
        domaines_clean = [s.strip() for s in domaines if s and s.strip()]

        # ports : garder seulement entiers valides
        ports_clean = []
        for p in ports_raw:
            p = str(p).strip()
            if not p:
                continue
            # accepter format "80" ou "80,443" si l'admin colle plusieurs dans un champ
            parts = re.split(r'[,\s;]+', p)
            for part in parts:
                if part.isdigit():
                    ports_clean.append(int(part))

        # Écrire dans rules.json
        rules_to_save = {
            "ips_suspectes": ips_clean,
            "apps_interdites": apps_clean,
            "domaines_blacklistes": domaines_clean,
            "ports_non_standards": ports_clean
        }
        with open(rules_path, "w", encoding="utf-8") as f:
            json.dump(rules_to_save, f, indent=4, ensure_ascii=False)

        # Optionnel : message flash puis redirect
        flash("✅ Règles mises à jour avec succès.", "success")
        return redirect(url_for('settings'))

    # GET : rendre le template
    return render_template("settings.html", rules=rules)


@app.route('/export_csv')
@login_required
def export_csv():
    anomalies_csv_path = os.path.join("static", "anomalies.csv")
    if not os.path.exists(anomalies_csv_path):
        return "Aucun fichier CSV généré."

    df = pd.read_csv(anomalies_csv_path)
    selected_columns = [
        'Anomalies_detectees', '_timestamp', 'app_category_name',
        'app_name', 'app_protocol', 'imsi_anonymized','client'
    ]
    if not all(col in df.columns for col in selected_columns):
        return "Colonnes manquantes pour générer le rapport CSV."

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join("static", "reports", f"rapport_anomalies_{timestamp}.csv")
    df[selected_columns].to_csv(path, index=False, encoding="utf-8-sig")

    # Sauvegarde en BD
    contenu_json = df[selected_columns].to_dict(orient="records")
    rapport = Rapport(
        user_id=current_user.id,
        type="csv",
        file_path=path,
        contenu=json.dumps(contenu_json, ensure_ascii=False)
    )
    db_session.add(rapport)
    db_session.commit()

    return send_file(path, as_attachment=True)


@app.route("/admin/users")
@login_required
@admin_required
def manage_users():
    users = db_session.query(User).order_by(User.created_at.desc()).all()
    return render_template("manage_users.html", users=users)


@app.route("/admin/user/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_user(user_id):
    user = db_session.query(User).get(user_id)
    if user:
        user.estactif = not user.estactif
        db_session.commit()
        flash(f"✅ Statut mis à jour pour {user.username}.", "success")
    return redirect(url_for("manage_users"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = db_session.query(User).get(user_id)
    if user:
        db_session.delete(user)
        db_session.commit()
        flash(f"🗑️ Utilisateur {user.username} supprimé.", "info")
    return redirect(url_for("manage_users"))


@app.route("/admin/user/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_user(user_id):
    user = db_session.query(User).get(user_id)
    if not user:
        flash("❌ Utilisateur introuvable.", "danger")
        return redirect(url_for("manage_users"))

    if request.method == "POST":
        # récupérer tous les champs
        user.username = request.form.get("username")
        user.email = request.form.get("email")
        user.role = request.form.get("role")
        user.estactif = bool(int(request.form.get("estactif", 1)))  
        new_password = request.form.get("password")

        if new_password:
            user.set_password(new_password)

        db_session.commit()
        flash("✅ Utilisateur mis à jour.", "success")
        return redirect(url_for("manage_users"))

    return render_template("edit_user.html", user=user)


if __name__ == '__main__':
    app.run(debug=True)


