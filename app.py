# app.py - Backend di ErasmusHousing
# Correzione per Message.__init__() non passando 'sender' come keyword.

from flask import Flask, jsonify, request, send_from_directory, redirect, url_for, session
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_mail import Mail, Message # Assicurati che Message sia importato correttamente
from google_auth_oauthlib.flow import Flow as GoogleFlow
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import os
import csv
import json
import uuid
import random
import string
from datetime import datetime, timedelta, timezone
from functools import wraps
import base64
import hmac
import hashlib

# --- Configurazione Applicazione ---
app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-!change-me!")
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/login/*": {"origins": "*"}}, supports_credentials=True)

# --- Configurazione Flask-Mail ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'sandbox.smtp.mailtrap.io')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 2525))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@erasmushousing.com') 
mail = Mail(app)

# --- Configurazione OAuth ---
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI_RELATIVE = "/login/google/callback"
FACEBOOK_APP_ID = os.environ.get("FACEBOOK_APP_ID")
FACEBOOK_APP_SECRET = os.environ.get("FACEBOOK_APP_SECRET")
FACEBOOK_REDIRECT_URI_RELATIVE = "/login/facebook/callback"

# --- Gestione Utenti e Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "serve_login_page"
login_manager.session_protection = "strong"
users_db = {}

class User(UserMixin):
    def __init__(self, id, name, email, password_hash=None, provider=None, profile_pic=None,
                 is_verified=False, email_verification_code=None, verification_code_expires=None):
        self.id = id; self.name = name; self.email = email; self.password_hash = password_hash
        self.provider = provider; self.profile_pic = profile_pic; self.is_verified = is_verified
        self.email_verification_code = email_verification_code
        self.verification_code_expires = verification_code_expires
        self.provider_ids = {}
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        if self.password_hash is None: return False
        return check_password_hash(self.password_hash, password)
    @staticmethod
    def get(user_id): return users_db.get(user_id)
    @staticmethod
    def find_by_email(email):
        for user_in_db in users_db.values():
            if user_in_db.email == email: return user_in_db
        return None
    @staticmethod
    def find_by_provider_id(p_name, p_id):
        for u_in_db in users_db.values():
            if u_in_db.provider_ids.get(p_name) == p_id: return u_in_db
        return None
    @staticmethod
    def create_or_update_social(p_name, p_id, name, email, pic):
        user_found = User.find_by_provider_id(p_name, p_id)
        if user_found: 
            user_found.name=name if name else user_found.name
            user_found.profile_pic=pic if pic else user_found.profile_pic
            user_found.email=email
            return user_found
        user_found = User.find_by_email(email)
        if user_found: 
            user_found.provider_ids[p_name]=p_id
            user_found.name=name if not user_found.name else user_found.name
            user_found.profile_pic=pic if not user_found.profile_pic else user_found.profile_pic
            if not user_found.is_verified: user_found.is_verified=True
            return user_found
        uid=str(uuid.uuid4())
        new_user=User(id=uid,name=name,email=email,provider=p_name,profile_pic=pic,is_verified=True)
        new_user.provider_ids[p_name]=p_id; users_db[uid]=new_user; return new_user
    @staticmethod
    def create_email_user(name, email, password):
        if User.find_by_email(email): return None
        uid=str(uuid.uuid4())
        user_created=User(id=uid,name=name,email=email,provider="email")
        user_created.set_password(password)
        user_created.generate_verification_code()
        users_db[uid]=user_created
        return user_created
    def generate_verification_code(self):
        self.email_verification_code=''.join(random.choices(string.digits,k=6))
        self.verification_code_expires=datetime.now(timezone.utc)+timedelta(minutes=30)
    def verify_email_code(self, code):
        if not self.is_verified and self.email_verification_code==code and \
           self.verification_code_expires and self.verification_code_expires > datetime.now(timezone.utc):
            self.is_verified=True; self.email_verification_code=None; self.verification_code_expires=None
            return True
        return False

@login_manager.user_loader
def load_user(user_id): return User.get(user_id)
@app.route('/login.html')
def serve_login_page(): return send_from_directory(app.static_folder, 'login.html')

def send_verification_email(user_email, code):
    try:
        user = User.find_by_email(user_email)
        user_name = user.name if user else "Utente"
        
        default_sender = app.config.get('MAIL_DEFAULT_SENDER')
        if not default_sender:
            app.logger.error("MAIL_DEFAULT_SENDER non è configurato nell'applicazione Flask! Impossibile inviare email.")
            return False

        # Message() chiamata senza 'sender=' keyword
        msg = Message("Verifica Email - ErasmusHousing",  # 1° argomento: Soggetto
                      recipients=[user_email])           # Argomento chiave per i destinatari
        
        msg.body = f"Ciao {user_name},\n\nIl tuo codice di verifica per ErasmusHousing è: {code}\n\n" \
                   f"Questo codice scadrà tra 30 minuti.\n\nSe non hai richiesto tu questa verifica, ignora questa email.\n\n" \
                   f"Grazie,\nIl Team di ErasmusHousing"
        
        mail.send(msg)
        app.logger.info(f"Email di verifica inviata a {user_email} (mittente di default: {default_sender})")
        return True
    except Exception as e:
        app.logger.error(f"MAIL SENDING ERROR per {user_email}: {e}") 
        return False

# --- Dati Mock Annunci ---
user_owner_1_id = str(uuid.uuid4()); users_db[user_owner_1_id] = User(id=user_owner_1_id, name="Prop Uno", email="owner1@example.com", provider="email", is_verified=True); users_db[user_owner_1_id].set_password("p")
user_owner_2_id = str(uuid.uuid4()); users_db[user_owner_2_id] = User(id=user_owner_2_id, name="Prop Due", email="owner2@example.com", provider="email", is_verified=True); users_db[user_owner_2_id].set_password("p")
mock_listings = [
    {"id": 1, "title": "Stanza Madrid", "city": "Madrid", "country": "Spagna", "type": "Stanza Singola", "price_eur_month": 450, "description": "...", "image_url": "...", "owner_id": user_owner_1_id, "availability_start_date": "2025-09-01", "availability_end_date": "2026-06-30"},
    {"id": 2, "title": "Monolocale Berlino", "city": "Berlino", "country": "Germania", "type": "Monolocale", "price_eur_month": 600, "description": "...", "image_url": "...", "owner_id": user_owner_2_id, "availability_start_date": "2025-10-15", "availability_end_date": None},
]
next_listing_id = 3

# --- "Database" per Messaggistica ---
conversations_db = {}; messages_db = {}
class Conversation:
    def __init__(self,id,u1,u2,l_id,ca=None,lma=None):self.id=id;self.participants=sorted([u1,u2]);self.listing_id=l_id;self.created_at=ca or datetime.now(timezone.utc);self.last_message_at=lma or self.created_at
    @staticmethod
    def find_by_participants_and_listing(u1,u2,l_id):sp=sorted([u1,u2]);return next((c for c in conversations_db.values() if c.participants==sp and c.listing_id==l_id),None)
    @staticmethod
    def get_for_user(uid):
        convos=[];
        for cid,c in conversations_db.items():
            if uid in c.participants:
                other_uid=next(p for p in c.participants if p!=uid);ou=User.get(other_uid);listing=next((l for l in mock_listings if l["id"]==c.listing_id),None)
                msgs=sorted([m for m in messages_db.values() if m.conversation_id==cid],key=lambda x:x.timestamp,reverse=True);last_m=msgs[0] if msgs else None
                convos.append({"conversation_id":c.id,"other_user_name":ou.name if ou else "N/D","other_user_id":other_uid,"listing_id":c.listing_id,"listing_title":listing["title"] if listing else "N/D","last_message_snippet":last_m.content[:30]+"..." if last_m and len(last_m.content)>30 else (last_m.content if last_m else ""),"last_message_timestamp":last_m.timestamp.isoformat() if last_m else c.last_message_at.isoformat(),"is_last_message_from_current_user":last_m.sender_id==uid if last_m else False})
        return sorted(convos,key=lambda x:x["last_message_timestamp"],reverse=True)
class Message:
    def __init__(self,id,c_id,s_id,r_id,content,l_id,ts=None,is_read=False):self.id=id;self.conversation_id=c_id;self.sender_id=s_id;self.receiver_id=r_id;self.content=content;self.listing_id=l_id;self.timestamp=ts or datetime.now(timezone.utc);self.is_read=is_read
    @staticmethod
    def get_for_conversation(c_id):return sorted([{"message_id":m.id,"sender_id":m.sender_id,"sender_name":User.get(m.sender_id).name if User.get(m.sender_id) else "N/D","content":m.content,"timestamp":m.timestamp.isoformat(),"is_read":m.is_read} for m in messages_db.values() if m.conversation_id==c_id],key=lambda x:x["timestamp"])

# --- Route Statiche ---
@app.route('/')
def index(): return send_from_directory(app.static_folder, 'index.html')
@app.route('/<path:filename>')
def serve_static_files(filename):
    allowed_html=['index.html','listings.html','listing-detail.html','add-listing.html','login.html','messages.html']
    if filename in allowed_html: return send_from_directory(app.static_folder,filename)
    if filename.startswith('images/'): return send_from_directory(app.static_folder,filename)
    if filename in ['app.py','requirements.txt','render.yaml','.env','instance','.git','.gitignore','README.md','LICENSE']: return jsonify({"error":"Access denied"}),403
    return send_from_directory(app.static_folder,filename)

# --- API Annunci ---
@app.route('/api/listings', methods=['GET'])
def get_listings():
    city_filter=request.args.get('city'); type_filter=request.args.get('type'); max_price_filter=request.args.get('max_price',type=int)
    cl=mock_listings
    if city_filter: cl=[l for l in cl if city_filter.lower() in l['city'].lower() or (l.get('country') and city_filter.lower() in l['country'].lower())]
    if type_filter: norm_tf=type_filter.lower().replace("_"," "); cl=[l for l in cl if l.get('type') and norm_tf==l['type'].lower()]
    if max_price_filter is not None: cl=[l for l in cl if l.get('price_eur_month') is not None and l['price_eur_month']<=max_price_filter]
    return jsonify(cl)
@app.route('/api/listings/<int:listing_id>', methods=['GET'])
def get_listing_detail(listing_id):
    listing=next((l for l in mock_listings if l["id"]==listing_id),None)
    if listing: owner=User.get(listing.get("owner_id"));data=listing.copy();data["owner_name"]=owner.name if owner else "N/D";data["availability_start_date"]=listing.get("availability_start_date");data["availability_end_date"]=listing.get("availability_end_date");return jsonify(data)
    return jsonify({"error":"Listing not found"}),404
@app.route('/api/listings', methods=['POST'])
@login_required
def add_listing():
    global next_listing_id;data=request.json
    if not data or not 'title' in data or not 'city' in data or not 'availability_start_date' in data: return jsonify({"error":"Dati mancanti."}),400
    new_listing={"id":next_listing_id,"title":data['title'],"city":data['city'],"country":data.get('country',''),"type":data.get('type','N/D'),"price_eur_month":data.get('price_eur_month',0),"description":data.get('description',''),"image_url":data.get('image_url',f'https://placehold.co/600x400?text=Alloggio+{next_listing_id}'),"owner_id":current_user.id,"availability_start_date":data['availability_start_date'],"availability_end_date":data.get('availability_end_date')} 
    mock_listings.append(new_listing);next_listing_id+=1;return jsonify(new_listing),201
    
# --- API Autenticazione ---
@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    if current_user.is_authenticated: return jsonify({"logged_in":True,"user":{"id":current_user.id,"name":current_user.name,"email":current_user.email,"profile_pic":current_user.profile_pic,"provider":current_user.provider,"is_verified":current_user.is_verified}})
    return jsonify({"logged_in":False})
@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout(): logout_user(); session.clear(); return jsonify({"message": "Logout successful"})
@app.route('/api/auth/register/email', methods=['POST'])
def register_email():
    data=request.get_json(); name=data.get('name'); email=data.get('email'); password=data.get('password')
    if not name or not email or not password: return jsonify({"error": "Nome, email e password sono obbligatori."}), 400
    if User.find_by_email(email): return jsonify({"error": "Un utente con questa email esiste già."}), 409
    user=User.create_email_user(name,email,password)
    if user:
        if send_verification_email(user.email,user.email_verification_code): return jsonify({"message": "Registrazione quasi completata! Controlla la tua email per il codice di verifica.", "email": user.email}), 201
        return jsonify({"error": "Utente creato, ma c'è stato un problema nell'invio dell'email di verifica. Riprova più tardi o contatta il supporto.", "email": user.email}), 500
    return jsonify({"error": "Errore durante la creazione dell'utente."}), 500
@app.route('/api/auth/verify/email', methods=['POST'])
def verify_email():
    data=request.get_json(); email=data.get('email'); code=data.get('code')
    if not email or not code: return jsonify({"error": "Email e codice sono obbligatori."}),400
    user=User.find_by_email(email)
    if not user: return jsonify({"error":"Utente non trovato."}),404
    if user.is_verified: return jsonify({"message":"Email già verificata."}),200
    if user.verify_email_code(code): login_user(user,remember=True); return jsonify({"message":"Email verificata! Login effettuato.","user":{"id":user.id,"name":user.name,"email":user.email,"is_verified":user.is_verified}}),200
    return jsonify({"error":"Codice non valido o scaduto."}),400
@app.route('/api/auth/resend-verification', methods=['POST'])
def resend_verification_email():
    data=request.get_json(); email=data.get('email')
    if not email: return jsonify({"error": "Email obbligatoria."}),400
    user=User.find_by_email(email)
    if not user: return jsonify({"error":"Utente non trovato."}),404
    if user.is_verified: return jsonify({"message":"Account già verificato."}),200
    if user.provider!="email": return jsonify({"error":"Verifica non richiesta per questo account."}),400
    user.generate_verification_code()
    if send_verification_email(user.email,user.email_verification_code): return jsonify({"message":"Nuova email di verifica inviata."}),200
    return jsonify({"error":"Errore nell'invio della nuova email di verifica."}),500
@app.route('/api/auth/login/email', methods=['POST'])
def login_email():
    data=request.get_json(); email=data.get('email'); password=data.get('password')
    if not email or not password: return jsonify({"error": "Dati mancanti."}),400
    user=User.find_by_email(email)
    if not user or not user.check_password(password): return jsonify({"error":"Credenziali non valide o account non esistente."}),401
    if user.provider!="email": return jsonify({"error":f"Account creato con {user.provider}."}),403
    if not user.is_verified: return jsonify({"error":"Il tuo account non è ancora verificato. Controlla l'email inviata al momento della registrazione o usa l'opzione per reinviare il codice.","unverified_account":True,"email":user.email}),403
    login_user(user,remember=True); return jsonify({"message":"Login OK!","user":{"id":user.id,"name":user.name,"email":user.email,"is_verified":user.is_verified}}),200

# --- OAuth Routes ---
def _get_scheme_and_host():
    app_base_url_env = os.environ.get("APP_BASE_URL")
    if app_base_url_env:
        app_base_url_env = app_base_url_env.rstrip('/')
        if not (app_base_url_env.startswith("https://") or app_base_url_env.startswith("http://localhost") or app_base_url_env.startswith("http://127.0.0.1")):
            app.logger.error(f"ERRORE CRITICO: APP_BASE_URL ('{app_base_url_env}') non https://.")
            return app_base_url_env 
        app.logger.info(f"Utilizzo APP_BASE_URL: {app_base_url_env}")
        return app_base_url_env
    else:
        if request.headers.get("X-Forwarded-Proto") == "https": base_url = f"https://{request.host.rstrip('/')}"; app.logger.warning(f"ATTENZIONE: APP_BASE_URL non impostata! Deducendo: '{base_url}'. IMPOSTA APP_BASE_URL."); return base_url
        else: base_url = request.url_root.rstrip('/'); app.logger.warning(f"ATTENZIONE: APP_BASE_URL non impostata e X-Forwarded-Proto non 'https'. Usando: '{base_url}'. Potrebbe essere 'http'. IMPOSTA APP_BASE_URL."); return base_url
def get_google_flow(state=None):
    base_url = _get_scheme_and_host(); redirect_uri = base_url + GOOGLE_REDIRECT_URI_RELATIVE
    app.logger.info(f"Google OAuth: redirect_uri: {redirect_uri}")
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET: app.logger.error("GOOGLE_CLIENT_ID/SECRET non configurati."); return None
    cfg={"web":{"client_id":GOOGLE_CLIENT_ID,"client_secret":GOOGLE_CLIENT_SECRET,"auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token"}}
    try: return GoogleFlow.from_client_config(client_config=cfg,scopes=["openid","email","profile"],redirect_uri=redirect_uri,state=state)
    except Exception as e: app.logger.error(f"Errore Google Flow con redirect_uri '{redirect_uri}': {e}"); return None
@app.route('/login/google')
def login_google_start():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET: return "Errore config Google.",500
    flow=get_google_flow();
    if not flow: return "Errore flow OAuth Google. Controlla log.",500
    auth_url,state=flow.authorization_url(access_type='offline',include_granted_scopes='true');session['oauth_state_google']=state;return redirect(auth_url)
@app.route(GOOGLE_REDIRECT_URI_RELATIVE)
def login_google_callback():
    flow=get_google_flow(state=session.get('oauth_state_google'))
    if not flow: return "Errore recupero flow OAuth Google.",500
    try: flow.fetch_token(authorization_response=request.url)
    except Exception as e: app.logger.error(f"Google fetch_token: {e}"); return f"Errore auth Google: {e}",400
    if not session.get("oauth_state_google")==request.args.get("state"): app.logger.warning("Google state mismatch."); return "Errore stato OAuth.",400
    creds=flow.credentials; resp=requests.get("https://www.googleapis.com/oauth2/v3/userinfo",headers={"Authorization":f"Bearer {creds.token}"})
    if not resp.ok: app.logger.error(f"Google userinfo: {resp.text}"); return "Errore recupero info Google.",500
    info=resp.json();gid=info.get("sub");email=info.get("email");name=info.get("name");pic=info.get("picture")
    if not email: return "Email non da Google.",400
    user=User.create_or_update_social("google",f"google_{gid}",name,email,pic);login_user(user,remember=True)
    return redirect(url_for('index',_external=True,_scheme=request.scheme))
@app.route('/login/facebook')
def login_facebook_start():
    if not FACEBOOK_APP_ID or not FACEBOOK_APP_SECRET: return "Errore config Facebook.",500
    base_url=_get_scheme_and_host(); r_uri=base_url+FACEBOOK_REDIRECT_URI_RELATIVE; app.logger.info(f"Facebook OAuth: redirect_uri: {r_uri}")
    state=str(uuid.uuid4());session['oauth_state_facebook']=state
    auth_url=(f"https://www.facebook.com/v12.0/dialog/oauth?client_id={FACEBOOK_APP_ID}&redirect_uri={r_uri}&state={state}&scope=email,public_profile");return redirect(auth_url)
@app.route(FACEBOOK_REDIRECT_URI_RELATIVE)
def login_facebook_callback():
    code=request.args.get('code');r_state=request.args.get('state')
    if not session.get('oauth_state_facebook')==r_state: app.logger.warning("Facebook state mismatch."); return "Errore stato OAuth FB.",400
    if not code: return "Codice FB mancante.",400
    base_url=_get_scheme_and_host(); r_uri=base_url+FACEBOOK_REDIRECT_URI_RELATIVE
    t_url=(f"https://graph.facebook.com/v12.0/oauth/access_token?client_id={FACEBOOK_APP_ID}&redirect_uri={r_uri}&client_secret={FACEBOOK_APP_SECRET}&code={code}");t_resp=requests.get(t_url)
    if not t_resp.ok: app.logger.error(f"FB token: {t_resp.text}"); return "Errore token FB.",500
    token=t_resp.json().get('access_token')
    if not token: app.logger.error(f"Access token FB non trovato: {t_resp.json()}"); return "Token FB non trovato.",500
    ui_url=(f"https://graph.facebook.com/me?fields=id,name,email,picture.type(large)&access_token={token}");ui_resp=requests.get(ui_url)
    if not ui_resp.ok: app.logger.error(f"FB userinfo: {ui_resp.text}"); return "Errore recupero info FB.",500
    info=ui_resp.json();fbid=info.get("id");email=info.get("email");name=info.get("name");pic=info.get("picture",{}).get("data",{}).get("url")
    if not email: app.logger.warning(f"Email non da FB per {name} (ID: {fbid})."); return "Email non da FB.",400
    user=User.create_or_update_social("facebook",f"facebook_{fbid}",name,email,pic);login_user(user,remember=True)
    return redirect(url_for('index',_external=True,_scheme=request.scheme))

# --- Facebook Deauthorize Callback ---
def base64_url_decode(inp): padding_factor=(4-len(inp)%4)%4;inp+="="*padding_factor;return base64.urlsafe_b64decode(inp)
def parse_signed_request_facebook(sr_str):
    if not FACEBOOK_APP_SECRET: app.logger.error("FACEBOOK_APP_SECRET non configurato."); return None
    try:
        esig,payload=sr_str.split('.',1);dsig=base64_url_decode(esig);data=json.loads(base64_url_decode(payload).decode('utf-8'))
        if data.get('algorithm','').upper()!='HMAC-SHA256': app.logger.error(f"Algoritmo sconosciuto: {data.get('algorithm')}"); return None
        xsig=hmac.new(FACEBOOK_APP_SECRET.encode('utf-8'),payload.encode('utf-8'),hashlib.sha256).digest()
        if hmac.compare_digest(dsig,xsig): return data
        else: app.logger.warning("Firma signed_request non valida."); return None
    except Exception as e: app.logger.error(f"Errore parsing signed_request: {e}"); return None
@app.route('/facebook/deauthorize', methods=['POST'])
def facebook_deauthorize_callback():
    sr_str=request.form.get('signed_request')
    if not sr_str: app.logger.warning("Chiamata a /deauthorize senza signed_request."); return "Richiesta non valida",400
    app.logger.info(f"Ricevuto signed_request deautorizzazione: {sr_str[:50]}...")
    data=parse_signed_request_facebook(sr_str)
    if data and 'user_id' in data:
        fb_uid=data['user_id']; app_scoped_fb_uid=f"facebook_{fb_uid}"
        u_deauth=User.find_by_provider_id("facebook",app_scoped_fb_uid)
        if u_deauth:
            app.logger.info(f"Deautorizzazione FB per utente (ID: {u_deauth.id}, Email: {u_deauth.email}, FB ID: {fb_uid}).")
            if "facebook" in u_deauth.provider_ids: del u_deauth.provider_ids["facebook"]
            if u_deauth.provider=="facebook" and not u_deauth.provider_ids: app.logger.info(f"Utente {u_deauth.id} si basava solo su FB.")
            print(f"Utente {u_deauth.email} (FB ID: {fb_uid}) deautorizzato.")
        else: app.logger.warning(f"Deautorizzazione per FB ID: {fb_uid}, ma utente non trovato.")
        return "Deautorizzazione ricevuta.",200
    else: app.logger.error("signed_request non valido o user_id mancante."); return "signed_request non valido",400

# --- API Messaggistica ---
@app.route('/api/conversations', methods=['GET'])
@login_required
def get_conversations(): user_convos=Conversation.get_for_user(current_user.id); return jsonify(user_convos)
@app.route('/api/conversations/<string:conversation_id>/messages', methods=['GET'])
@login_required
def get_messages_for_conversation(c_id):
    convo=conversations_db.get(c_id)
    if not convo or current_user.id not in convo.participants: return jsonify({"error":"Conversazione non trovata."}),404
    msgs=Message.get_for_conversation(c_id)
    for mid_str,mobj in list(messages_db.items()): 
        if mobj.conversation_id==c_id and mobj.receiver_id==current_user.id and not mobj.is_read: 
            mobj.is_read=True
    return jsonify(msgs)
@app.route('/api/messages/send', methods=['POST'])
@login_required
def send_message():
    data=request.get_json();r_id=data.get('receiver_id');l_id=data.get('listing_id',type=int);content=data.get('content')
    if not r_id or not l_id or not content: return jsonify({"error":"Dati mancanti."}),400
    if r_id==current_user.id: return jsonify({"error":"Non puoi inviarti messaggi."}),400
    receiver=User.get(r_id);
    if not receiver: return jsonify({"error":"Destinatario non trovato."}),404
    listing=next((l for l in mock_listings if l["id"]==l_id),None);
    if not listing: return jsonify({"error":"Annuncio non trovato."}),404
    convo=Conversation.find_by_participants_and_listing(current_user.id,r_id,l_id)
    if not convo: cid=str(uuid.uuid4());convo=Conversation(id=cid,user1_id=current_user.id,user2_id=r_id,listing_id=l_id);conversations_db[cid]=convo
    mid=str(uuid.uuid4());new_msg=Message(id=mid,conversation_id=convo.id,sender_id=current_user.id,receiver_id=r_id,content=content,listing_id=l_id)
    messages_db[mid]=new_msg;convo.last_message_at=new_msg.timestamp 
    msg_data={"message_id":new_msg.id,"conversation_id":new_msg.conversation_id,"sender_id":new_msg.sender_id,"sender_name":current_user.name,"content":new_msg.content,"timestamp":new_msg.timestamp.isoformat(),"is_read":False}
    return jsonify({"message":"Messaggio inviato.","sent_message":msg_data,"conversation_id":convo.id}),201

if __name__ == '__main__':
    print("\n--- VERIFICA CONFIGURAZIONE OAuth & Email ---")
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET: print("ATTENZIONE: GOOGLE_CLIENT_ID o SECRET non impostati.")
    else: print("Configurazione Google OAuth: OK")
    if not FACEBOOK_APP_ID or not FACEBOOK_APP_SECRET: print("ATTENZIONE: FACEBOOK_APP_ID o SECRET non impostati.")
    else: print("Configurazione Facebook OAuth: OK")
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'): print("ATTENZIONE: MAIL_USERNAME o PASSWORD non impostati.")
    else: print(f"Configurazione Email: OK (Server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']})")
    print("-------------------------------------\n")
    port = int(os.environ.get("PORT", 10000))
    app.run(debug=True, host='0.0.0.0', port=port)

