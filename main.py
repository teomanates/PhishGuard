import os.path
import time
import requests  # HTTP istekleri yapmak için kullanılır.
import hashlib  # Dosya ve dizin işlemleri için kullanılır.
import base64  # Base64 kodlama ve çözme işlemleri için kullanılır.
import re # Düzenli ifadeler (regex) ile metin işleme için kullanılır.
from bs4 import BeautifulSoup  # HTML ve XML belgelerini ayrıştırmak için kullanılır.
from google.auth.transport.requests import Request #Google API token'ını yenilemek için gerekli istek (HTTP) aracı.
from google.oauth2.credentials import Credentials # Daha önce alınmış token bilgilerinden kimlik bilgisi (credentials) oluşturmak için.
from google_auth_oauthlib.flow import InstalledAppFlow # OAuth (kullanıcı giriş sistemi) ile Google hesabına bağlanmayı sağlar.
from googleapiclient.discovery import build  #Gmail API servis nesnesini oluşturmak için kullanılır.
from googleapiclient.errors import HttpError # API işlemlerinde hata oluşursa bu sınıf kullanılarak yakalanır.
from thefuzz import fuzz # Metin benzerliği ölçmek için kullanılır (örneğin, e-posta adreslerinin karşılaştırılması için).

# uygulamanın hangi izinlere ihtiyaç duyduğunu belirtir
# .readonly izinleri sadece okuma erişimi için kullanılır
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def extract_links(html_content):
    """
    Verilen HTML içeriğinden hem <a> etiketlerindeki linkleri hem de
    düz metin içindeki URL'leri ayıklar.
    """
    if not html_content:
        return []
    
    # 1. Yol: Klasik <a> etiketlerini BeautifulSoup ile bulalım
    soup = BeautifulSoup(html_content, 'html.parser')
    html_links = {a['href'] for a in soup.find_all('a', href=True)} # set kullanarak dublikeleri engelle

    # 2. Yol: Düz metin içindeki URL'leri RegEx ile bulalım
    # E-postanın sadece görünür metnini alalım
    plain_text = soup.get_text()
    # Bu RegEx, http/https/ftp ile başlayan URL'leri bulur
    regex = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    regex_links = set(re.findall(regex, plain_text))

    # İki yöntemle bulduğumuz tüm linkleri birleştirelim
    all_links = list(html_links.union(regex_links))
    
    return all_links


def check_links_with_virustotal(link, api_key): # Virustotal API ile linkleri kontrol eder

    if not api_key or 'Your API Key' in api_key:  # Eğer API anahtarı eksik veya hatalı ise
        print("\n[HATA] VirusTotal API anahtarı girilmemiş veya hatalı! Lütfen main.py dosyasını kontrol edin.\n")
        return "API_KEY_MISSING", 0

    url_id = base64.urlsafe_b64encode(link.encode()).decode().strip('=')
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"  # Virustotal API URL'si oluşturur
    
    headers = {
        "x-apikey": api_key  # Virustotal API anahtarını başlıklara ekler
    }


    try:
        response = requests.get(url, headers=headers, timeout=15)  # Virustotal API'ye GET isteği gönderir
       
        if response.status_code == 429 or response.status_code == 204:
            return "API_LIMIT_EXCEEDED", 0

        if response.status_code == 200:  # Eğer istek başarılı ise
            result = response.json()  # JSON formatında yanıtı alır
            stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})


            malicious_count = stats.get('malicious', 0)  # Kötü amaçlı yazılım sayısını alır, yoksa 0 döner
            suspicious_count = stats.get('suspicious', 0)  # Şüpheli sayısını alır, yoksa 0 döner

            total_dangerous_count = malicious_count + suspicious_count  # Toplam tehlikeli sayıyı hesaplar
            if total_dangerous_count > 0:
                return "DANGEROUS", total_dangerous_count
            else:
                return "SAFE", 0
        
        elif response.status_code == 404:  # Eğer URL bulunamazsa
            return "NOT_FOUND", 0  # URL bulunamadı

        else: # Eğer başka bir hata oluşursa
            return "API_ERROR", 0

    except requests.RequestException as e:  # İstek sırasında bir hata oluşursa
        return "REQUEST_ERROR", 0  # Hata mesajını döner    




def get_email_body(payload): # E-postanın karmaşık 'payload' yapısını çözerek okunabilir metin gövdesini çıkarır. HTML içeriği önceliklendirir, yoksa düz metni alır.
    if 'parts' in payload:  # Eğer e-posta parçalar halinde geliyorsa
        for part in payload['parts']:  # Çok parçalı mail'lerde (multipart/alternative) genellikle hem text/plain hem de text/html olur. HTML olanı tercih ederiz çünkü linkler ve formatlama oradadır.
            if part['mimeType'] == 'text/html':  # Eğer parça HTML ise
                data = part['body']['data']  # HTML içeriği alır
                return base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8')  # Base64 kodlamasını çözer ve UTF-8 olarak döner

            if part['mimeType'] == 'text/plain':  # Eğer parça düz metin ise
                data = part['body']['data']
                return base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8')

    elif 'body' in payload and payload['body']['size'] > 0:
        data = payload['body']['data']  # Eğer tek parça ise
        return base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8')  # Base64 kodlamasını çözer ve UTF-8 olarak döner

    return ''  # Eğer içerik yoksa boş string döner


def analyze_email_content(subject,sender, body_html): # E-posta içeriğini analiz eder, HTML etiketlerini temizler ve düz metin olarak döner.Risk skoru döndürür.
    risk_score = 0  # Başlangıçta risk skoru 0 olarak ayarlanır
    analysis_details = []  # Analiz detaylarını saklamak için boş bir liste

    suspicious_keywords = {
    "acil": 10,
    "hemen": 10,
    "şifre": 15,
    "parola": 15,
    "hesabınız": 10,
    "askıya alındı": 20,
    "kapatılacaktır": 20,
    "doğrulayın": 15,
    "güncelleyin": 15,
    "kazandınız": 25,
    "ödül": 25,
    "tebrikler": 20,
    "fatura": 5,
    "ödeme": 10,
    "tıklayın": 10,
    "giriş yapın": 15,
    "banka": 10,
    "kredi kartı": 20,
    "sınırlı süreli": 15,
    "teklif": 10,
    "kaçırmayın": 15,

    # İngilizce anahtar kelimeler
    "verify your account": 20,
    "account suspended": 25,
    "click here": 15,
    "login now": 15,
    "update your information": 15,
    "your account has been locked": 25,
    "unusual activity": 20,
    "limited time offer": 15,
    "confirm your identity": 20,
    "urgent action required": 20
    }


    soup = BeautifulSoup(body_html, 'html.parser')  # HTML içeriğini ayrıştırır
    content_text = soup.get_text()  # HTML etiketlerini temizler ve düz metin olarak alır
    # İçeriği küçük harfe çevirerek daha kolay arama yapalım
    content_lower = content_text.lower()
    subject_lower = subject.lower()

    for keyword, score in suspicious_keywords.items():
        if keyword in content_lower or keyword in subject_lower:
            risk_score += score
            analysis_details.append(f"'{keyword}' kelimesi bulundu, risk skoru +{score}")

    """ 
    2. Gönderen Analizi (Basit)
    Örnek: "bilgi@guvenilirsite.com" gibi bir mail yerine "guvenilirsite@sahtesite.net" gibi aldatmacalar
    Bu kısmı şimdilik basit tutalım, ileride geliştirilebilir.
    Örneğin, gönderen adında "Microsoft" geçip mail adresi "@hotmail.com" değilse şüphelidir.

    """
    try:
        #göndereni görünen ad ve eposta adresi olarak ayır
        sender_name = ""
        sender_email = ""
        if '<' in sender and '>' in sender:
            sender_name = sender.split('<')[0].strip().replace('"', '').lower()# Gönderen adını alır 
            sender_email = sender.split('<')[1].split('>')[0].strip().lower()
        else:
            sender_email = sender.strip().lower()

        # epostadan domaini ve TLD'yi alalım
        if '@' in sender_email:
            domain = sender_email.split('@')[1]
            tld = domain.split('.')[-1]  # TLD'yi alır 

            # görünen ad ve domain tutarsızlığı kontrolü
            trusted_brands = ["google", "microsoft", "apple", "facebook", "instagram", "twitter", 
                              "amazon", "netflix", "spotify", "paypal", "turkcell", "vodafone", 
                              "türk telekom", "garanti", "akbank", "iş bankası", "ziraat", "yapı kredi"]

            for brand in trusted_brands:
                if brand in sender_name and brand not in domain:
                    risk_score += 40
                    analysis_details.append(f"Gönderen adı '{sender_name}' güvenilir marka '{brand}' içeriyor ama domain '{domain}' içermiyor, risk skoru +40")
                    break
            
            for brand in trusted_brands:
                clean_brand = brand.replace(" ", "").replace("-", "")

                domain_main_part = domain.split('.')[0]  # Domainin ana kısmını alır (örneğin, "gmail" için "gmail.com" veya "hotmail" için "hotmail.com")

                similarity_ratio = fuzz.ratio(clean_brand, domain_main_part)  # FuzzyWuzzy ile benzerlik oranını hesaplar

                if similarity_ratio > 80 and similarity_ratio < 100:
                    risk_score += 50  # Eğer benzerlik oranı %80 ile %100 arasında ise risk skoru artırılır  
                    analysis_details.append(f"Alan adı taklidi şüphesi (Benzerlik: {similarity_ratio}%): '{domain}' vs '{brand}' (risk skoru +50)")
                    break

            
            suspicious_tlds = ["xyz", "top", "club", "info", "online", "buzz", "tk", "ml", "ga", "cf", "gq", "work", "link"]
            
            if tld in suspicious_tlds:
                risk_score += 25
                analysis_details.append(f" Güvenilirliği düşük alan adı uzantısı: '.{tld}' (risk skoru +25)")

    except Exception as e:
        analysis_details.append(f"Gönderen analizi hatası: {str(e)}")

    
    #link analizi
    links = extract_links(body_html)  # E-postanın içeriğinden linkleri çıkarır
    

    return risk_score, analysis_details, links  # Risk skoru ve analiz detaylarını döner


def main():
    """ Gmail API'ye baglanir ve okunammis son 5 e-postanin gonderen ve konusunu listeler. """

    # --- YENİ KONFİGÜRASYON OKUMA KISMI ---
    config = configparser.ConfigParser()
    config.read('config.ini')

    gmail_credentials_path = config.get('GMAIL', 'credentials_path')
    virustotal_api_key = config.get('VIRUSTOTAL', 'api_key')
    risk_threshold = config.getint('SETTINGS', 'risk_threshold')

    creds = None 
    # token.json dosyasi, kullanici kimlik bilgilerini saklar, ve yenileme tokenlerini saklar
    # ilk calistirmada otomatik olarak olusturulur
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # eger kimlik bilgileri yoksa veya gecersizse, kullanici girişi yapilmasi gerekir
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token: # token süresi dolmuş ama yenileme izni varsa, otomatik olarak yeniler
            creds.refresh(Request())

        else: 
            flow = InstalledAppFlow.from_client_secrets_file(  # Eğer ilk defa çalışıyorsan, credentials.json dosyasından yeni bir oturum başlatır (OAuth flow başlatılır).
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0) # Yerel bir tarayıcı penceresi açar, kullanıcı giriş yapar, izin verir ve kimlik bilgileri alınır.

        with open('token.json', 'w') as token:  # Alınan kimlik bilgileri token.json dosyasına kaydedilir.
            token.write(creds.to_json())
    
    try:
        service = build('gmail', 'v1', credentials=creds)  # Gmail API servisi oluşturulur.
        
        results = service.users().messages().list(userId='me', labelIds=['UNREAD'], maxResults=5).execute()  # Okunmamış e-postalar listelenir.
        messages = results.get('messages', [])  # E-postalar alınır, yoksa boş döner.

        if not messages:
            print('Hiç okunmamış e-posta yok.')
            return

        print("--- PhishGuard Analizi Başlatılıyor ---")
        print("\n")

        

        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()  # E-postanın içeriği alınır, 'full' formatında yani tüm detaylarıyla.

            payload = msg['payload']  # E-postanın payload'u alınır, bu kısım e-postanın içeriğini ve başlıklarını içerir.
            headers = payload['headers']  # E-postanın başlık bilgileri alınır (From, Subject, vs.).
            subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')  # E-posta konusunu alır, yoksa 'No Subject' döner.
            sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Gönderen Bilinmiyor')  # Göndereni alır, yoksa 'Gönderen Bilinmiyor' döner.

            body = get_email_body(payload)  # E-postanın gövdesi alınır, HTML veya düz metin olarak.

            if not body:  # Eğer gövde boşsa, kullanıcıya bilgi verir.
                continue


            risk_score, analysis_details, links = analyze_email_content(subject,sender,body)  # E-posta içeriği analiz edilir, risk skoru ve detaylar döner.

            links_scan_details = []
            if links:
                links_scan_details.append(f"Toplam {len(links)} link bulundu. Taranıyor...")
                for link in links[:4]:
                    status, dangerous_count = check_links_with_virustotal(link, virustotal_api_key)  # Her link için VirusTotal API ile kontrol yapılır.

                    if status == "DANGEROUS":
                        risk_score += 100
                        links_scan_details.append(f"!!! TEHLİKELİ LİNK: {link} ({dangerous_count} motor)\n")
                    elif status in ["API_KEY_MISSING", "API_LIMIT_EXCEEDED"]:
                        links_scan_details.append(f"[UYARI] VirusTotal API sorunu: {status}")
                        break
                    
                    
                    print("[BİLGİ] API limitine takılmamak için 16 saniye bekleniyor...")
                    time.sleep(16)
                    

            print(f"Gönderen: {sender}")
            print(f"Konu: {subject}")
            #print(f"Risk Skoru: {risk_score}")

            if risk_score >= risk_threshold:  # Eğer risk skoru belirlenen eşiği aşıyorsa, kullanıcıya uyarı verir.
                print("⚠️ Uyarı: Bu e-posta şüpheli görünüyor! ⚠️")

                print("Detaylar:")
                for detail in analysis_details:
                    print(f"- {detail}")
                    
                for detail in links_scan_details:
                    print(f"  - {detail}")
            
            else:
                print("✅ Bu e-posta güvenli görünüyor.\n")
        
        print("\n--- PhishGuard Analizi Tamamlandı ---")
        

    except HttpError as error:  # API isteklerinde hata oluşursa yakalar.
        print(f'Hata oluştu: {error}')

if __name__ == '__main__':
    main()  # Ana fonksiyonu çalıştırır.