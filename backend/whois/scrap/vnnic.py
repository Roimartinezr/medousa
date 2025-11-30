import os
import time
import requests
import google.generativeai as genai
from google.api_core import exceptions as google_exceptions
from bs4 import BeautifulSoup
from PIL import Image
from io import BytesIO
from dotenv import load_dotenv 
import json

# --- 1. CONFIGURACIÓN ---
load_dotenv()
API_KEY = os.getenv("GOOGLE_API_KEY")

if not API_KEY:
    raise ValueError("❌ Error: No se encontró GOOGLE_API_KEY en variables de entorno.")

genai.configure(api_key=API_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

def resolver_captcha(imagen_bytes):
    for i in range(2):
        try:
            img = Image.open(BytesIO(imagen_bytes))
            prompt = "Return ONLY the alphanumeric characters inside this CAPTCHA image. No spaces."
            response = model.generate_content([prompt, img])
            text = response.text.strip().replace(" ", "")
            return text
        except google_exceptions.ResourceExhausted:
            time.sleep(5)
        except Exception as e:
            print(f"⚠️ Error IA: {e}")
            return None
    return None

def extraer_datos_diccionario(html_completo):
    """
    Convierte el bloque HTML 'domain_info' en un diccionario Python.
    """
    soup = BeautifulSoup(html_completo, 'html.parser')
    datos = {}

    contenedor = soup.select_one('div.domain_info')

    if contenedor:
        items = contenedor.find_all('li')
        for li in items:
            label_span = li.find('span', class_='whois_label')
            info_span = li.find('span', class_='whois_information')

            if label_span and info_span:
                key = label_span.get_text(strip=True).rstrip(':').strip()
                value = info_span.get_text(separator=' ', strip=True)
                datos[key] = value
    return datos

async def main(dominio):
    session = requests.Session()
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
        "Referer": "https://vnnic.vn/whois-information"
    }
    session.headers.update(headers)
    
    url_base = "https://vnnic.vn"
    url_whois = "https://vnnic.vn/whois-information"

    print("1. Conectando a VNNIC...")
    
    # --- LÓGICA DE REINTENTO (2 Intentos para errores de conexión) ---
    r = None
    max_retries = 2
    for attempt in range(max_retries):
        try:
            r = session.get(url_whois)
            # Si llegamos aquí sin error, salimos del bucle
            break 
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"⚠️ Conexión abortada. Reintentando en 2s... (Intento {attempt+1}/{max_retries})")
                time.sleep(2)
            else:
                print(f"❌ Error conexión definitivo: {e}")
                return {} # Devolvemos dicc vacío en error

    soup = BeautifulSoup(r.text, 'html.parser')

    # --- 2. CAPTCHA ---
    img_tag = soup.find('img', {'alt': 'Image CAPTCHA'})
    if not img_tag:
        img_tag = soup.find('img', src=lambda x: x and '/image_captcha' in x)

    if not img_tag:
        print("❌ No se encontró CAPTCHA.")
        return {}

    src_captcha = img_tag.get('src')
    if not src_captcha.startswith('http'): src_captcha = url_base + src_captcha

    print("2. Resolviendo Captcha...")
    try:
        r_img = session.get(src_captcha)
    except Exception as e:
        print(f"❌ Error descargando imagen captcha: {e}")
        return {}

    codigo_captcha = resolver_captcha(r_img.content)
    
    if not codigo_captcha:
        print("❌ Fallo IA Captcha.")
        return {}
    
    print(f"🤖 Captcha: {codigo_captcha}")

    # --- 3. PAYLOAD ---
    form = img_tag.find_parent('form')
    payload = {"domainname": dominio, "captcha_response": codigo_captcha}
    
    if form:
        for h in form.find_all('input', type='hidden'):
            if h.get('name'): payload[h.get('name')] = h.get('value')
        btn = form.find('input', type='submit') or form.find('button', type='submit')
        if btn and btn.get('name'): payload[btn.get('name')] = btn.get('value')
        
        post_url = url_whois
        if form.get('action'):
            action = form.get('action')
            if action != post_url:
                post_url = action if action.startswith('http') else url_base + action
    else:
        print("❌ Error aislando formulario.")
        return {}

    print(f"3. Obteniendo datos de: {dominio}...")
    try:
        r_post = session.post(post_url, data=payload)
    except Exception as e:
        print(f"❌ Error enviando formulario: {e}")
        return {}

    # --- 4. RESULTADO ---
    # Comprobar redirección (Búsqueda global)
    soup_res = BeautifulSoup(r_post.text, 'html.parser')
    titulo = soup_res.title.get_text().lower() if soup_res.title else ""
    if "tìm kiếm" in titulo:
        print("⚠️  AVISO: Redirección detectada (Posible Captcha incorrecto).")
        return {}

    # Si encontramos el div de información, devolvemos los datos
    if "domain_info" in r_post.text:
        print(f"🔒 El dominio {dominio} está OCUPADO. Extrayendo...")
        return extraer_datos_diccionario(r_post.text)

    # Si está disponible o hay error, devolvemos vacío
    elif "is available" in r_post.text.lower() or "chưa đăng ký" in r_post.text.lower():
        print(f"✅ El dominio {dominio} está DISPONIBLE.")
        return {}
        
    else:
        print("❓ Estado desconocido o error de Captcha.")
        return {}

"""if __name__ == "__main__":
    # Ejecutamos la consulta
    # La función main ya devuelve SOLO el diccionario de datos (o vacío)
    datos = main("ftp.vn")

    print("\n" + "="*30)
    print("RESULTADO JSON:")
    print(json.dumps(datos, indent=4, ensure_ascii=False))
    print("="*30)"""