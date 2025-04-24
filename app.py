import os
import requests
from flask import Flask, request, redirect, url_for, render_template, session, make_response
from datetime import datetime
from dotenv import load_dotenv
import logging # Za bolje logovanje grešaka u konzolu servera
try:
    # Pokušavamo da importujemo zoneinfo
    import zoneinfo
except ImportError:
    # Ako ne uspe, postavićemo ga na None da znamo kasnije
    zoneinfo = None
    logging.warning("Biblioteka 'zoneinfo' nije dostupna (možda treba 'pip install tzdata'). Koristiće se vreme servera.")


load_dotenv()

app = Flask(__name__)
# Proveravamo da li je FLASK_SECRET_KEY postavljen
flask_key = os.getenv('FLASK_SECRET_KEY')
if not flask_key:
    logging.critical("FATALNA GREŠKA: FLASK_SECRET_KEY nije postavljen u .env fajlu!")
    exit()
app.secret_key = flask_key

# Konfiguracija logovanja u konzolu
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Preuzimanje konstanti iz .env fajla i provera
DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
DISCORD_GUILD_ID = os.getenv('DISCORD_GUILD_ID')
DISCORD_ROLE_ID = os.getenv('DISCORD_ROLE_ID')
REDIRECT_URI = os.getenv('REDIRECT_URI')
DISCORD_LOG_CHANNEL_ID = os.getenv('DISCORD_LOG_CHANNEL_ID') # NOVO: Učitavamo ID log kanala

# Provera da li su sve OBAVEZNE varijable učitane
required_vars = {
    "DISCORD_CLIENT_ID": DISCORD_CLIENT_ID,
    "DISCORD_CLIENT_SECRET": DISCORD_CLIENT_SECRET,
    "DISCORD_BOT_TOKEN": DISCORD_BOT_TOKEN,
    "DISCORD_GUILD_ID": DISCORD_GUILD_ID,
    "DISCORD_ROLE_ID": DISCORD_ROLE_ID,
    "REDIRECT_URI": REDIRECT_URI,
    "DISCORD_LOG_CHANNEL_ID": DISCORD_LOG_CHANNEL_ID # Dodajemo i ovo u proveru
}

missing_vars = [key for key, value in required_vars.items() if not value]
if missing_vars:
    logging.critical(f"FATALNA GREŠKA: Nedostaju sledeće obavezne varijable u .env fajlu: {', '.join(missing_vars)}")
    exit()


API_ENDPOINT = 'https://discord.com/api/v10'
LOG_FILE = "auth_log.txt" # Definišemo ime log fajla

# Funkcija za bezbedno logovanje u fajl
def log_to_file(message):
    try:
        with open(LOG_FILE, "a", encoding='utf-8') as f:
            f.write(f"{datetime.now()} - {message}\n")
    except Exception as e:
        logging.error(f"Greška pri upisu u log fajl ({LOG_FILE}): {e}")

# Funkcija za dobijanje IP adrese (uzimajući u obzir proxy)
def get_ip_address():
    if request.headers.getlist("X-Forwarded-For"):
       ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
       ip = request.remote_addr
    return ip

# --- Rute ---

# Početna stranica - može da sadrži dugme za login
@app.route('/')
def home():
    # Renderuje index.html koji bi trebalo da ima link ka /login
    return render_template('index.html')

# Ruta koja inicira Discord OAuth2 proces
@app.route('/login')
def login():
    scope = 'identify' # Dovoljno za dobijanje ID-ja i Taga
    discord_auth_url = (
        f'{API_ENDPOINT}/oauth2/authorize'
        f'?client_id={DISCORD_CLIENT_ID}'
        f'&redirect_uri={REDIRECT_URI}'
        f'&response_type=code'
        f'&scope={scope}'
    )
    logging.info(f"Preusmeravanje korisnika na Discord Auth URL.")
    return redirect(discord_auth_url)

# Ruta na koju Discord vraća korisnika NAKON autorizacije
@app.route('/callback')
def callback():
    code = request.args.get('code')
    ip_address = get_ip_address()

    if not code:
        logging.warning(f"Callback pozvan bez 'code' parametra. IP: {ip_address}")
        return render_template('error.html', message='Autorizacioni kod nije pronađen u odgovoru od Discorda.'), 400

    try:
        # Korak 1: Zameni 'code' za 'access_token'
        token_data = {
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        logging.info(f"Slanje zahteva za token za korisnika sa IP: {ip_address}")
        response_token = requests.post(f'{API_ENDPOINT}/oauth2/token', data=token_data, headers=headers)
        response_token.raise_for_status()
        token_json = response_token.json()
        access_token = token_json.get('access_token')

        if not access_token:
             logging.error(f"Access token nije primljen od Discorda iako je status bio uspešan? Odgovor: {token_json}")
             raise ValueError("Access token nije primljen od Discorda.")

        # Korak 2: Dobij informacije o korisniku
        user_headers = {'Authorization': f'Bearer {access_token}'}
        logging.info(f"Slanje zahteva za user info za korisnika sa IP: {ip_address}")
        response_user = requests.get(f'{API_ENDPOINT}/users/@me', headers=user_headers)
        response_user.raise_for_status()
        user_info = response_user.json()
        user_id = user_info['id']
        username = user_info['username']
        discriminator = user_info.get('discriminator', '0')
        user_tag = f"{username}#{discriminator}" if discriminator != '0' else username
        logging.info(f"Uspešno dobijeni podaci za korisnika: {user_tag} ({user_id})")

        # Korak 3: Loguj IP adresu, Discord Tag i ID u fajl
        log_message_file = f"IP: {ip_address} - User: {user_tag} ({user_id})"
        log_to_file(log_message_file)
        logging.info(f"Podaci logovani u fajl za korisnika: {user_tag} ({user_id})")

        # Korak 4: Dodeli rolu korisniku koristeći BOT TOKEN
        role_url = f'{API_ENDPOINT}/guilds/{DISCORD_GUILD_ID}/members/{user_id}/roles/{DISCORD_ROLE_ID}'
        bot_headers_role = {
            'Authorization': f'Bot {DISCORD_BOT_TOKEN}',
            'User-Agent': 'AndrijaAppRoleAssigner (https://www.andrija.com, v1.0)'
        }
        logging.info(f"Pokušaj dodele role {DISCORD_ROLE_ID} korisniku {user_id} na serveru {DISCORD_GUILD_ID}")
        response_role = requests.put(role_url, headers=bot_headers_role, timeout=10) # Dodat timeout

        # Provera uspeha dodele role
        if response_role.status_code == 204:
            logging.info(f"Rola {DISCORD_ROLE_ID} uspešno dodeljena korisniku {user_id}")
            log_to_file(f"SUCCESS - Role assigned for {user_tag} ({user_id})")

            # ===>>> NOVI DEO: Slanje poruke u Discord Log Kanal <<<===
            try:
                if DISCORD_LOG_CHANNEL_ID: # Proveravamo da li je ID kanala uopšte definisan
                    # Formatiranje vremena
                    formatted_time = "Nepoznato vreme"
                    try:
                        if zoneinfo: # Proveravamo da li smo uspešno importovali zoneinfo
                            belgrade_tz = zoneinfo.ZoneInfo("Europe/Belgrade")
                            now_belgrade = datetime.now(belgrade_tz)
                            formatted_time = now_belgrade.strftime("%d.%m.%Y u %H:%M:%S")
                        else: # Fallback ako zoneinfo nije dostupan
                            formatted_time = datetime.now().strftime("%d.%m.%Y u %H:%M:%S (Server Time)")
                    except Exception as time_e:
                         logging.error(f"Greška pri formatiranju vremena za Discord log: {time_e}")
                         formatted_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S (Fallback)")

                    # Kreiranje poruke
                    discord_log_message = (
                        f"✅ Korisnik **{user_tag}** ({user_id}) je verifikovan dana {formatted_time} "
                        f"i ima IP adresu: `{ip_address}`"
                    )

                    # Slanje poruke
                    message_payload = {'content': discord_log_message}
                    message_url = f'{API_ENDPOINT}/channels/{DISCORD_LOG_CHANNEL_ID}/messages'
                    bot_headers_msg = {
                        'Authorization': f'Bot {DISCORD_BOT_TOKEN}',
                        'Content-Type': 'application/json',
                        'User-Agent': 'AndrijaAppLogger (https://www.andrija.com, v1.0)'
                    }
                    logging.info(f"Slanje log poruke u Discord kanal {DISCORD_LOG_CHANNEL_ID}")
                    msg_response = requests.post(message_url, headers=bot_headers_msg, json=message_payload, timeout=10)

                    # Provera uspeha slanja poruke (logujemo grešku ali ne prekidamo korisnika)
                    if msg_response.status_code >= 400:
                        logging.error(f"Greška prilikom slanja log poruke u Discord ({msg_response.status_code}): {msg_response.text}")
                        log_to_file(f"DISCORD_LOG_ERROR {msg_response.status_code} - User: {user_tag} ({user_id}) - {msg_response.text}")
                    else:
                        logging.info(f"Log poruka uspešno poslata u Discord kanal {DISCORD_LOG_CHANNEL_ID}")
                else:
                    logging.warning("DISCORD_LOG_CHANNEL_ID nije podešen u .env, preskačem slanje Discord loga.")
                    log_to_file(f"DISCORD_LOG_SKIP - User: {user_tag} ({user_id}) - Log channel ID missing.")

            except Exception as discord_log_err:
                logging.exception(f"Neočekivana greška prilikom slanja Discord log poruke: {discord_log_err}")
                log_to_file(f"DISCORD_LOG_UNEXPECTED_ERROR - User: {user_tag} ({user_id}) - {discord_log_err}")
            # ===>>> KRAJ NOVOG DELA <<<===

            # Prikazujemo stranicu o uspehu
            try:
                logging.info("Pokušaj renderovanja success.html")
                rendered_template = render_template('success.html', user_tag=user_tag)
                logging.info("Renderovanje success.html uspešno.")
                return rendered_template
            except Exception as render_err:
                 logging.exception(f"GREŠKA pri renderovanju success.html: {render_err}")
                 log_to_file(f"RENDER_ERROR - success.html - {render_err}")
                 # Vraćamo generičku grešku ako renderovanje success stranice ne uspe
                 return render_template('error.html', message='Došlo je do greške pri prikazu stranice potvrde.')

        # Obrada grešaka prilikom dodele role (ako status nije bio 204)
        elif response_role.status_code == 403:
            logging.error(f"Greška 403 prilikom dodele role korisniku {user_id}: Bot nema dozvolu ili je rola viša od botove.")
            log_to_file(f"ROLE_ERROR 403 - User: {user_tag} ({user_id}) - Bot nema dozvolu ili rola hijerarhija.")
            return render_template('error.html', message='Bot nema potrebne dozvole da vam dodeli rolu ili je došlo do problema sa hijerarhijom rola. Obratite se administratoru.')
        elif response_role.status_code == 404:
            logging.error(f"Greška 404 prilikom dodele role korisniku {user_id}: Korisnik ili rola nisu pronađeni na serveru.")
            log_to_file(f"ROLE_ERROR 404 - User: {user_tag} ({user_id}) - Korisnik/rola nije pronađena.")
            return render_template('error.html', message='Došlo je do greške: Korisnik ili rola nisu pronađeni. Moguće je da niste član servera.')
        else:
            error_message = f"Greška prilikom dodele role. Status: {response_role.status_code}. Odgovor: {response_role.text}"
            logging.error(error_message + f" (User: {user_id})")
            log_to_file(f"ROLE_ERROR {response_role.status_code} - User: {user_tag} ({user_id}) - {response_role.text}")
            return render_template('error.html', message=f'Došlo je do greške ({response_role.status_code}) prilikom dodele role. Obratite se administratoru.')

    # Obrada grešaka od ranijih koraka (token exchange, user info fetch)
    except requests.exceptions.RequestException as e:
        error_details = e.response.text if e.response else str(e)
        logging.error(f"Greška u komunikaciji sa Discord API: {error_details} (IP: {ip_address})")
        log_to_file(f"API_ERROR - IP: {ip_address} - {error_details}")
        return render_template('error.html', message='Došlo je do greške u komunikaciji sa Discordom. Pokušajte ponovo.')
    # Obrada svih ostalih neočekivanih grešaka
    except Exception as e:
        logging.exception(f"Neočekivana greška u callback ruti: {e} (IP: {ip_address})")
        log_to_file(f"GENERAL_ERROR - IP: {ip_address} - {e}")
        return render_template('error.html', message='Došlo je do neočekivane serverske greške.')


if __name__ == '__main__':
    logging.info("Pokretanje Flask development servera...")
    # Za produkciju, koristite pravi WSGI server kao Gunicorn ili Waitress
    # i postavite debug=False
    app.run(debug=False, host='0.0.0.0', port=5000)