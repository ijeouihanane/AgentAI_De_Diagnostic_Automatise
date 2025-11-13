# anomalies.py
import pandas as pd
import numpy as np
import json
import os

def load_rules():
    rules_path = os.path.join(os.path.dirname(__file__), "rules.json")
    if not os.path.exists(rules_path):
        # Si absent, renvoyer des valeurs par défaut pour éviter erreur
        return {
            "ips_suspectes": [],
            "apps_interdites": [],
            "domaines_blacklistes": [],
            "ports_non_standards": []
        }
    with open(rules_path, "r", encoding="utf-8") as f:
        return json.load(f)

def clean_data(df):
    """
    Nettoie et prépare les données pour la détection d'anomalies.
    """
    required_columns = [
        'imsi_anonymized', '_timestamp', 'flow_dst_l4_port_id', 'l4_proto_name',
        'http_req_method', 'app_category_name', 'http_url_host_domain',
        'flow_in_bytes', 'flow_out_bytes', 'flow_bytes', 'app_name', 'flow_dst_ip_addr',
        'customer_name_anonymized', 'msisdn_anonymized'
    ]
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Colonnes manquantes : {missing_columns}")

    df['http_req_method'] = df['http_req_method'].fillna('')
    df['app_category_name'] = df['app_category_name'].fillna('')
    df['http_url_host_domain'] = df['http_url_host_domain'].fillna('')
    df['app_name'] = df['app_name'].fillna('')
    df['flow_in_bytes'] = pd.to_numeric(df['flow_in_bytes'], errors='coerce').fillna(0)
    df['flow_out_bytes'] = pd.to_numeric(df['flow_out_bytes'], errors='coerce').fillna(0)
    df['flow_bytes'] = pd.to_numeric(df['flow_bytes'], errors='coerce').fillna(0)
    df['flow_dst_l4_port_id'] = pd.to_numeric(df['flow_dst_l4_port_id'], errors='coerce').fillna(0)
    df['_timestamp'] = pd.to_datetime(df['_timestamp'], errors='coerce')
    df = df.dropna(subset=['_timestamp', 'imsi_anonymized'])
    
    return df


def write_anomalies_to_db(anomalies_df, engine, table_name="anomalies_detected", if_exists="append"):
    """
    Écrit les anomalies détectées dans la base PostgreSQL.
    """
    anomalies_df.to_sql(table_name, engine, if_exists=if_exists, index=False)
    return len(anomalies_df)


def detect_anomalies(df):
    """
    Détecte les anomalies dans les données et ajoute des colonnes pour les rapports.
    """
    import json, os

    df = clean_data(df)

    # Charger les règles depuis rules.json (si existe)
    rules_path = os.path.join(os.path.dirname(__file__), "rules.json")
    if os.path.exists(rules_path):
        with open(rules_path, "r", encoding="utf-8") as f:
            rules = json.load(f)
    else:
        # fallback : valeurs par défaut
        rules = {
            "ips_suspectes": ['192.0.2.1', '203.0.113.5', '10.10.10.10'],
            "apps_interdites": ['P2P', 'Streaming', 'Jeux'],
            "domaines_blacklistes": ['badsite.com', 'malware.example'],
            "ports_non_standards": [8080, 8888, 5000, 3000, 9999]
        }

    # Initialiser colonnes
    df['timestamp'] = df['_timestamp']
    df['timestamp_hour'] = df['timestamp'].dt.floor('h')
    df['Anomalies_detectees'] = ""
    df['anomaly_type'] = ""

    # === HTTP sur port non standard ===
    condition_http = (
        (df['l4_proto_name'].str.lower() == 'tcp') &
        (df['flow_dst_l4_port_id'].isin(rules.get("ports_non_standards", []))) &
        (df['http_req_method'].str.len() > 0)
    )
    df.loc[condition_http, 'Anomalies_detectees'] += "HTTP sur port non standard; "
    df.loc[condition_http, 'anomaly_type'] = "HTTP_PORT"

    # === Apps interdites ===
    df.loc[df['app_category_name'].isin(rules.get("apps_interdites", [])), 'Anomalies_detectees'] += "Accès à application interdite; "
    df.loc[df['app_category_name'].isin(rules.get("apps_interdites", [])), 'anomaly_type'] = "APP_FORBIDDEN"

    # === Domaines blacklistés ===
    df.loc[df['http_url_host_domain'].isin(rules.get("domaines_blacklistes", [])), 'Anomalies_detectees'] += "Accès domaine blacklisté; "
    df.loc[df['http_url_host_domain'].isin(rules.get("domaines_blacklistes", [])), 'anomaly_type'] = "BLACKLIST"

    # === Trafic GTP-U anormal ===
    df['gtp_ratio'] = df['flow_in_bytes'] / (df['flow_out_bytes'] + 1)
    gtp_anormal = (
        (df['app_name'].str.contains("GTP", na=False)) &
        ((df['flow_bytes'] > df['flow_bytes'].quantile(0.95)) | 
         (df['gtp_ratio'] > df['gtp_ratio'].quantile(0.95)))
    )
    df.loc[gtp_anormal, 'Anomalies_detectees'] += "Trafic GTP-U anormal; "
    df.loc[gtp_anormal, 'anomaly_type'] = "GTP_ANOMALY"

    # === IPs suspectes ===
    df.loc[df['flow_dst_ip_addr'].isin(rules.get("ips_suspectes", [])), 'Anomalies_detectees'] += "Communication avec IP suspecte; "
    df.loc[df['flow_dst_ip_addr'].isin(rules.get("ips_suspectes", [])), 'anomaly_type'] = "SUSPECT_IP"

    # === Trop d’anomalies SIM ===
    anomalies = df[df['Anomalies_detectees'] != ""]
    anomalies_par_sim = anomalies.groupby(['imsi_anonymized', 'timestamp_hour']).size().reset_index(name='count')
    sims_frequentes = anomalies_par_sim[anomalies_par_sim['count'] > 5]
    
    df = df.merge(sims_frequentes[['imsi_anonymized', 'timestamp_hour']], 
                  on=['imsi_anonymized', 'timestamp_hour'], how='left', indicator=True)
    df.loc[df['_merge'] == 'both', 'Anomalies_detectees'] += "Trop d’anomalies en 1h; "
    df.loc[df['_merge'] == 'both', 'anomaly_type'] = "HIGH_FREQ"
    df = df.drop(columns=['_merge'])

    # Filtrer uniquement les anomalies
    anomalies_df = df[df['Anomalies_detectees'] != ""].copy()

    # Colonnes supplémentaires
    anomalies_df['client'] = anomalies_df['customer_name_anonymized']
    anomalies_df['msisdn'] = anomalies_df['msisdn_anonymized']
    anomalies_df['ip_port'] = anomalies_df['flow_dst_ip_addr'] + ':' + anomalies_df['flow_dst_l4_port_id'].astype(str)
    anomalies_df['app_protocol'] = anomalies_df['app_name']

    expected_columns = [
        'imsi_anonymized', '_timestamp', 'flow_dst_l4_port_id', 'l4_proto_name',
        'http_req_method', 'app_category_name', 'http_url_host_domain',
        'flow_in_bytes', 'flow_out_bytes', 'flow_bytes', 'app_name', 'flow_dst_ip_addr',
        'customer_name_anonymized', 'msisdn_anonymized', 'timestamp', 'timestamp_hour',
        'Anomalies_detectees', 'gtp_ratio', 'client', 'msisdn', 'ip_port', 'app_protocol',
        'anomaly_type'
    ]
    anomalies_df = anomalies_df[expected_columns]

    return anomalies_df
