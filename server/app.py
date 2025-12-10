from flask import Flask, send_file, request, make_response, jsonify, Response
from werkzeug.middleware.proxy_fix import ProxyFix
import ipaddress
from datetime import datetime, timezone, timedelta
import uuid
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import os
import re
from io import BytesIO
from PIL import Image
import json
import threading
from collections import deque
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# Configuration depuis variables d'environnement
USERNAME = os.getenv('USERNAME','admin')
PASSWORD =  os.getenv('PASSWORD','password')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'False').lower() == 'true'
LOG_PATH = os.getenv('LOG_PATH', 'logs')
WEBHOOK_URL = os.getenv('WEBHOOK_URL', '')
MAX_LOG_SIZE = int(os.getenv('MAX_LOG_SIZE', 10485760))  # 10MB par défaut
BACKUP_COUNT = int(os.getenv('BACKUP_COUNT', 5))
ENABLE_GEOLOCATION = os.getenv('ENABLE_GEOLOCATION', 'False').lower() == 'true'
DATA_FILE = os.getenv('DATA_FILE', 'tracking_data.json')
MAX_DATA_ENTRIES = int(os.getenv('MAX_DATA_ENTRIES', 10000))  # Limite d'entrées

# Configuration proxy (si derrière reverse proxy)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Plages d'adresses internes (RFC 1918 + loopback + link-local)
INTERNAL_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Private A
    ipaddress.ip_network("172.16.0.0/12"),    # Private B
    ipaddress.ip_network("192.168.0.0/16"),   # Private C
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 private
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]

# Cache en mémoire pour les données récentes (évite trop d'I/O)
data_cache = deque(maxlen=1000)
cache_lock = threading.Lock()

# Configuration du logging structuré
def setup_logging():
    """Configure un système de logging robuste avec rotation"""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    # Handler pour fichier avec rotation
    file_handler = RotatingFileHandler(
        LOG_PATH + "tracking.log",
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # Handler pour console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Configuration du logger
    logger = logging.getLogger('PixelTracker')
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

def initialize_data_file():
    """Initialise le fichier JSON de données s'il n'existe pas"""
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f)
        logger.info(f"Fichier de données créé: {DATA_FILE}")
    else:
        # Charger les données existantes dans le cache
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
                with cache_lock:
                    data_cache.extend(existing_data[-1000:])  # Derniers 1000 éléments
                logger.info(f"Chargé {len(existing_data)} entrées depuis {DATA_FILE}")
        except Exception as e:
            logger.error(f"Erreur chargement données existantes: {str(e)}")

def save_tracking_data(tracking_data):
    """Sauvegarde les données de tracking dans le fichier JSON"""
    try:
        # Ajouter au cache en mémoire
        with cache_lock:
            data_cache.append(tracking_data)
        
        # Lecture du fichier existant
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = []
        
        # Ajout de la nouvelle entrée
        data.append(tracking_data)
        
        # Limitation du nombre d'entrées (rotation)
        if len(data) > MAX_DATA_ENTRIES:
            data = data[-MAX_DATA_ENTRIES:]
            logger.info(f"Rotation des données: conservation des {MAX_DATA_ENTRIES} dernières entrées")
        
        # Écriture atomique (via fichier temporaire)
        temp_file = f"{DATA_FILE}.tmp"
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        # Remplacement atomique
        os.replace(temp_file, DATA_FILE)
        
    except Exception as e:
        logger.error(f"Erreur sauvegarde données: {str(e)}", exc_info=True)

def sanitize_log_value(value, max_length=500):
    """Nettoie et tronque les valeurs pour éviter les injections de logs"""
    if not isinstance(value, str):
        value = str(value)
    
    # Suppression des caractères de contrôle dangereux
    value = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', value)
    
    # Remplacement des retours à la ligne et tabulations
    value = value.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    
    # Troncature si trop long
    if len(value) > max_length:
        value = value[:max_length] + '...[TRUNCATED]'
    
    return value

def extract_real_ip(request_obj):
    """Extrait l'IP réelle en gérant correctement X-Forwarded-For"""
    x_forwarded_for = request_obj.headers.get('X-Forwarded-For', '')
    
    if x_forwarded_for:
        # Prend la première IP de la chaîne (client original)
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request_obj.remote_addr or 'unknown'
    
    # Validation de l'IP
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        logger.warning(f"IP invalide détectée: {sanitize_log_value(ip)}")
        return request_obj.remote_addr or 'unknown'

def is_internal_ip(ip_str):
    """Détermine si l'IP appartient à une plage interne"""
    try:
        ip_addr = ipaddress.ip_address(ip_str)
        return any(ip_addr in net for net in INTERNAL_NETS)
    except ValueError:
        return False

def hash_ip(ip_str, salt=None):
    """Hash l'IP pour anonymisation (RGPD-friendly)"""
    if salt is None:
        salt = os.getenv('IP_SALT', 'default-salt-change-me')
    
    return hashlib.sha256(f"{ip_str}{salt}".encode()).hexdigest()[:16]

def generate_transparent_pixel():
    """Génère un pixel transparent 1x1 en mémoire"""
    img = Image.new('RGBA', (1, 1), (0, 0, 0, 0))
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    return img_io

def send_webhook_alert(data):
    """Envoie une alerte webhook (Discord, Slack, etc.)"""
    if not WEBHOOK_URL:
        return
    
    try:
        import requests
        payload = {
            "content": f"🚨 **Accès externe détecté**",
            "embeds": [{
                "title": "Nouveau hit externe",
                "color": 16711680,  # Rouge
                "fields": [
                    {"name": "IP (hash)", "value": data.get('ip_hash', 'N/A'), "inline": True},
                    {"name": "Pays", "value": data.get('country', 'N/A'), "inline": True},
                    {"name": "User-Agent", "value": data.get('user_agent', 'N/A')[:100]},
                    {"name": "Referer", "value": data.get('referer', 'none')[:100]},
                    {"name": "URL", "value": data.get('url', 'N/A')[:100]},
                ],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }]
        }
        requests.post(WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        logger.error(f"Échec envoi webhook: {str(e)}")

def get_geolocation(ip_str):
    """Obtient la géolocalisation (nécessite une API externe)"""
    if not ENABLE_GEOLOCATION:
        return None
    try:
        import requests
        response = requests.get(
            f"http://ip-api.com/json/{ip_str}?fields=status,country,countryCode,city,isp",
            timeout=2
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'XX'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }
    except Exception as e:
        logger.debug(f"Géolocalisation échouée: {str(e)}")
    
    return None

@app.route("/")
@app.route("/pixel.png")
@app.route("/track")
def pixel_tracker():
    """Endpoint principal du Dashboard HTML"""
    try:
        # Extraction des données
        real_ip = extract_real_ip(request)
        user_agent = sanitize_log_value(request.headers.get("User-Agent", "unknown"))
        referer = sanitize_log_value(request.headers.get("Referer", "none"))
        method = request.method
        url = sanitize_log_value(request.url)
        host = sanitize_log_value(request.host)
        
        # Timestamp précis
        timestamp = datetime.now(timezone.utc)
        date_str = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # Millisecondes
        
        # ID unique pour ce hit
        hit_id = str(uuid.uuid4())
        
        # Classification interne/externe
        is_internal = is_internal_ip(real_ip)
        status = "INTERNAL" if is_internal else "EXTERNAL"
        
        # Hash de l'IP pour anonymisation
        ip_hash = real_ip # hash_ip(real_ip)
        
        # Géolocalisation (optionnelle)
        geo_data = None
        if not is_internal and ENABLE_GEOLOCATION:
            geo_data = get_geolocation(real_ip)
        
        # Préparation des données structurées
        tracking_data = {
            "timestamp": date_str,
            "hit_id": hit_id,
            "ip_hash": ip_hash,
            "ip_full": real_ip if DEBUG_MODE else None,  # Seulement en debug
            "type": status,
            "user_agent": user_agent,
            "method": method,
            "url": url,
            "host": host,
            "referer": referer,
            "geo": geo_data
        }
        
        # Logging structuré (JSON)
        log_entry = json.dumps(tracking_data, ensure_ascii=False)
        logger.info(log_entry)
        
        # Sauvegarde dans le fichier JSON (thread séparé pour ne pas bloquer)
        threading.Thread(target=save_tracking_data, args=(tracking_data,), daemon=True).start()
        
        # Alerte pour accès externes
        if status == "EXTERNAL":
            send_webhook_alert(tracking_data)
        
        # Génération et envoi du pixel
        pixel_img = generate_transparent_pixel()
        response = make_response(send_file(
            pixel_img,
            mimetype="image/png",
            as_attachment=False,
            download_name="pixel.png"
        ))
        
        # Headers de sécurité et anti-cache
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["ETag"] = hit_id
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Timing header (pour analytics)
        response.headers["X-Response-Time"] = f"{(datetime.now(timezone.utc) - timestamp).total_seconds() * 1000:.2f}ms"
        
        return response
    
    except Exception as e:
        logger.error(f"Erreur dans pixel_tracker: {str(e)}", exc_info=True)
        # Retourne quand même un pixel en cas d'erreur
        pixel_img = generate_transparent_pixel()
        return send_file(pixel_img, mimetype="image/png")



def check_auth(username, password):
    return username == USERNAME and password == PASSWORD

def authenticate():
    """Renvoie 401 pour demander l'auth"""
    return Response(
        'Authentification requise', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

@app.route("/dashboard")
def dashboard():
    """Sert le dashboard HTML avec auth"""
    auth = request.authorization
    if not auth or not check_auth(auth.username, auth.password):
        return authenticate()
    return send_file("dashboard.html")

@app.route("/api/logs")
def api_logs():
    """API pour récupérer les logs depuis le fichier JSON"""
    try:
        limit = request.args.get('limit', 100, type=int)
        time_filter = request.args.get('filter', '1h')
        
        # Lecture du fichier JSON
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                all_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Fallback sur le cache en mémoire si le fichier est inaccessible
            with cache_lock:
                all_data = list(data_cache)
        
        # Filtrer par temps
        now = datetime.now(timezone.utc)
        if time_filter == '1h':
            cutoff = now - timedelta(hours=1)
        elif time_filter == '24h':
            cutoff = now - timedelta(days=1)
        elif time_filter == '7d':
            cutoff = now - timedelta(days=7)
        else:  # 30d
            cutoff = now - timedelta(days=30)
     
        # Filtrage et tri
        filtered_logs = []
        for log in reversed(all_data):  # Parcourir du plus récent au plus ancien
            try:
                log_timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00')) 
                cutoff_naive = cutoff.replace(tzinfo=None)
                if log_timestamp > cutoff_naive:
                    filtered_logs.append(log)
                    if len(filtered_logs) >= limit:
                        break
            except (KeyError, ValueError) as e:
                logger.debug(f"Log invalide ignoré: {e}")
                continue
        
        return jsonify(filtered_logs)
    
    except Exception as e:
        logger.error(f"Erreur API logs: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/api/stats")
def api_stats():
    """API pour récupérer les statistiques agrégées"""
    try:
        time_filter = request.args.get('filter', '1h')
        
        # Lecture des données
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                all_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            with cache_lock:
                all_data = list(data_cache)
        
        # Filtrer par temps
        now = datetime.now(timezone.utc)
        if time_filter == '1h':
            cutoff = now - timedelta(hours=1)
        elif time_filter == '24h':
            cutoff = now - timedelta(days=1)
        elif time_filter == '7d':
            cutoff = now - timedelta(days=7)
        else:  # 30d
            cutoff = now - timedelta(days=30)
        
        filtered_data = [
            log for log in all_data
            if datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00')) > cutoff
        ]
        
        # Calculs statistiques
        total = len(filtered_data)
        internal = sum(1 for log in filtered_data if log.get('type') == 'INTERNAL')
        external = sum(1 for log in filtered_data if log.get('type') == 'EXTERNAL')
        
        # Top pays
        countries = {}
        for log in filtered_data:
            if log.get('geo') and log['geo'].get('country'):
                country = log['geo']['country']
                countries[country] = countries.get(country, 0) + 1
        
        top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Top user agents
        user_agents = {}
        for log in filtered_data:
            ua = log.get('user_agent', 'unknown')[:50]  # Tronqué
            user_agents[ua] = user_agents.get(ua, 0) + 1
        
        top_user_agents = sorted(user_agents.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return jsonify({
            "total_hits": total,
            "internal_hits": internal,
            "external_hits": external,
            "top_countries": [{"country": c, "count": n} for c, n in top_countries],
            "top_user_agents": [{"user_agent": ua, "count": n} for ua, n in top_user_agents],
            "time_range": time_filter
        })
    
    except Exception as e:
        logger.error(f"Erreur API stats: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500
      
@app.route("/health")
def health_check():
    """Endpoint de santé pour monitoring"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "Pixel Tracker"
    }), 200

@app.errorhandler(404)
def not_found(e):
    """Toutes les 404 retournent le pixel (tracking flexible)"""
    return pixel_tracker()

@app.errorhandler(500)
def internal_error(e):
    """Gestion des erreurs 500"""
    logger.error(f"Erreur serveur: {str(e)}", exc_info=True)
    pixel_img = generate_transparent_pixel()
    return send_file(pixel_img, mimetype="image/png"), 200

def print_banner():
    banner = """
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║   ███╗   ███╗ █████╗ ██╗██╗      ██████╗ ██╗   ██╗ █████╗ ██████╗  ║
║   ████╗ ████║██╔══██╗██║██║     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗ ║
║   ██╔████╔██║███████║██║██║     ██║  ███╗██║   ██║███████║██████╔╝ ║
║   ██║╚██╔╝██║██╔══██║██║██║     ██║   ██║██║   ██║██╔══██║██╔══██╗ ║
║   ██║ ╚═╝ ██║██║  ██║██║███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║ ║
║   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ║
║                                                                    ║
║                  Advanced Pixel Tracker v1.0                       ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

  Configuration:
   • Mode Debug: {debug}
   • Log File: {LOG_PATH}
   • Webhook: {webhook}
   • Geolocation: {geo}

  Serveur démarré avec succès!
   Endpoints disponibles:
   • GET /              → Pixel tracker
   • GET /pixel.png     → Pixel tracker
   • GET /track         → Pixel tracker
   • GET /dashboard     → Dashboard HTML
   • GET /health        → Health check
   • GET /api/stats     → Statistics 
   • GET /api/logs      → Logs JSON 

""".format(
        debug=" Enabled" if DEBUG_MODE else " Disabled",
        LOG_PATH=LOG_PATH,
        webhook=" Configured" if WEBHOOK_URL else " Not set",
        geo=" Enabled" if ENABLE_GEOLOCATION else " Disabled"
    )
    print(banner)

if __name__ == "__main__":
    print_banner()
    
    # Configuration serveur
    port = int(os.getenv('PORT', 8080))
    host = os.getenv('HOST', '0.0.0.0')
    
    if DEBUG_MODE:
        logger.warning("MODE DEBUG ACTIVÉ - Ne pas utiliser en production!")
        app.run(host=host, port=port, debug=True)
    else:
        logger.info(f"Mode production - Serveur sur {host}:{port}")
        app.run(host=host, port=port, debug=False)