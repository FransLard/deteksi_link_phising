import re
import urllib.parse
from urllib.parse import urlparse
import ipaddress
import requests
import urllib3
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import socket
import signal
from contextlib import contextmanager
import concurrent.futures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'shorturl.at', 'lc.chat', 'bl.ink', 'href.li', 'shorte.st',
    'cutt.ly', 'rb.gy', 't.co', 'cli.gs', 'u.to', 'tr.im',
    'v.gd', 'db.tt', 'qr.ae', 'cur.lv', 'bc.vc', 'soo.gd',
    'rubyurl.com', 'tiny.cc', 'y2u.be', '2.gp', 'tiny.pl',
    'link.zip.net', 'adf.ly', 'shrinkurl.in', 'tiny.ie'
}

PHISHING_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'loan',
    'download', 'bid', 'win', 'racing', 'accountant', 'science'
}

IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}')

URL_SHORTENER_PATTERN = re.compile(r'.*bit\.ly|tinyurl|goo\.gl|ow\.ly|is\.gd|buff\.ly|shorturl|lc\.chat|bl\.ink|href\.li|shorte\.st|cutt\.ly|rb\.gy|t\.co|cli\.gs|u\.to|tr\.im|v\.gd|db\.tt|qr\.ae|cur\.lv|bc\.vc|soo\.gd|rubyurl|tiny\.cc|y2u\.be|2\.gp|tiny\.pl|link\.zip|adf\.ly|shrinkurl|tiny\.ie', re.IGNORECASE)

class FeatureExtractor:
    FEATURE_NAMES = [
        'having_IP_Address',
        'URL_Length',
        'Shortining_Service',
        'having_At_Symbol',
        'double_slash_redirecting',
        'Prefix_Suffix',
        'having_Sub_Domain',
        'SSLfinal_State',
        'Domain_registeration_length',
        'favicon',
        'port',
        'HTTPS_token',
        'Request_URL',
        'URL_of_Anchor',
        'Links_in_tags',
        'SFH',
        'Submitting_to_email',
        'Abnormal_URL',
        'Redirect',
        'on_mouseover',
        'RightClick',
        'popUpWindow',
        'Iframe',
        'age_of_domain',
        'DNSRecord',
        'web_traffic',
        'Page_Rank',
        'Google_Index',
        'Links_pointing_to_page',
        'Statistical_report',
    ]

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.features = {}
        self._session = requests.Session()
        self._session.verify = False
        self._session.timeout = (3, timeout)

    def extract_all(self, url):
        self.features = {}
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = self._clean_domain(domain)

        self.features['having_IP_Address'] = self._having_ip_address(domain)
        self.features['URL_Length'] = self._url_length(url)
        self.features['Shortining_Service'] = self._shortining_service(url)
        self.features['having_At_Symbol'] = self._having_at_symbol(url)
        self.features['double_slash_redirecting'] = self._double_slash_redirecting(url)
        self.features['Prefix_Suffix'] = self._prefix_suffix(domain)
        self.features['having_Sub_Domain'] = self._having_sub_domain(domain)
        self.features['SSLfinal_State'] = self._ssl_final_state(url, parsed)
        self.features['Domain_registeration_length'] = self._domain_registration_length(domain)
        self.features['favicon'] = self._favicon(url)
        self.features['port'] = self._port(parsed)
        self.features['HTTPS_token'] = self._https_token(domain)
        self.features['Request_URL'] = self._request_url(url, parsed)
        self.features['URL_of_Anchor'] = self._url_of_anchor(url)
        self.features['Links_in_tags'] = self._links_in_tags(url)
        self.features['SFH'] = self._sfh(url)
        self.features['Submitting_to_email'] = self._submitting_to_email(url)
        self.features['Abnormal_URL'] = self._abnormal_url(url, domain)
        self.features['Redirect'] = self._redirect(url)
        self.features['on_mouseover'] = self._on_mouseover(url)
        self.features['RightClick'] = self._right_click(url)
        self.features['popUpWindow'] = self._popup_window(url)
        self.features['Iframe'] = self._iframe(url)
        self.features['age_of_domain'] = self._age_of_domain(domain)
        self.features['DNSRecord'] = self._dns_record(domain)
        self.features['web_traffic'] = self._web_traffic(url)
        self.features['Page_Rank'] = self._page_rank(url)
        self.features['Google_Index'] = self._google_index(url)
        self.features['Links_pointing_to_page'] = self._links_pointing_to_page(url)
        self.features['Statistical_report'] = self._statistical_report(url)

        return self.features

    def to_dataframe_row(self):
        import pandas as pd
        return pd.DataFrame([self.features])

    def get_feature_vector(self):
        return [self.features[name] for name in self.FEATURE_NAMES]

    def _clean_domain(self, netloc):
        if ':' in netloc:
            netloc = netloc.split(':')[0]
        return netloc.lower()

    def _having_ip_address(self, domain):
        try:
            ipaddress.ip_address(domain)
            return -1
        except ValueError:
            return 1

    def _url_length(self, url):
        length = len(url)
        if length < 54:
            return 1
        elif 54 <= length <= 75:
            return 0
        else:
            return -1

    def _shortining_service(self, url):
        if URL_SHORTENER_PATTERN.match(url):
            return -1
        return 1

    def _having_at_symbol(self, url):
        if '@' in url:
            return -1
        return 1

    def _double_slash_redirecting(self, url):
        pos = url.find('//', 8)
        if pos != -1:
            return -1
        return 1

    def _prefix_suffix(self, domain):
        if '-' in domain:
            return -1
        return 1

    def _having_sub_domain(self, domain):
        dot_count = domain.count('.')
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        else:
            return -1

    def _ssl_final_state(self, url, parsed):
        if parsed.scheme == 'https':
            try:
                response = self._session.get(url, timeout=(1.5, self.timeout))
                return 1
            except:
                return 0
        else:
            return -1

    def _domain_registration_length(self, domain):
        try:
            w = whois.whois(domain)
            if w.expiration_date:
                exp_date = w.expiration_date
                if isinstance(exp_date, list):
                    exp_date = exp_date[0]
                now = datetime.now()
                delta = exp_date - now
                if delta.days > 365:
                    return 1
                else:
                    return -1
            return 0
        except:
            return 0

    def _favicon(self, url):
        try:
            parsed = urlparse(url)
            favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
            response = self._session.get(favicon_url, timeout=(2, 3))
            if response.status_code == 200:
                return 1
            return -1
        except:
            return 0

    def _port(self, parsed):
        port = parsed.port
        if port is None:
            return 1
        preferred_ports = {80, 443, 21, 22, 25, 110, 143, 3306, 8080}
        if port in preferred_ports:
            return 1
        return -1

    def _https_token(self, domain):
        if 'https' in domain:
            return -1
        return 1

    def _request_url(self, url, parsed):
        try:
            response = self._session.get(url, timeout=(1.5, self.timeout))
            soup = BeautifulSoup(response.text, 'html.parser')
            total_requests = 0
            external_requests = 0
            for tag in soup.find_all(['img', 'script', 'link']):
                src = tag.get('src') or tag.get('href')
                if src:
                    total_requests += 1
                    if not src.startswith(parsed.scheme + '://' + parsed.netloc):
                        external_requests += 1
            if total_requests == 0:
                return 0
            ratio = external_requests / total_requests
            if ratio < 0.22:
                return 1
            elif 0.22 <= ratio <= 0.61:
                return 0
            else:
                return -1
        except:
            return 0

    def _url_of_anchor(self, url):
        try:
            response = self._session.get(url, timeout=(1.5, self.timeout))
            soup = BeautifulSoup(response.text, 'html.parser')
            parsed = urlparse(url)
            anchors = soup.find_all('a')
            if not anchors:
                return 1
            external_anchors = 0
            for a in anchors:
                href = a.get('href', '')
                if href.startswith('#') or href.startswith('javascript:'):
                    external_anchors += 1
                elif href and not href.startswith(parsed.scheme + '://' + parsed.netloc) and not href.startswith('/'):
                    external_anchors += 1
            ratio = external_anchors / len(anchors)
            if ratio < 0.31:
                return 1
            elif 0.31 <= ratio <= 0.67:
                return 0
            else:
                return -1
        except:
            return 0

    def _links_in_tags(self, url):
        try:
            response = self._session.get(url, timeout=(1.5, self.timeout))
            soup = BeautifulSoup(response.text, 'html.parser')
            parsed = urlparse(url)
            meta_links = soup.find_all(['link', 'meta', 'script'])
            if not meta_links:
                return 1
            external_links = 0
            for tag in meta_links:
                src = tag.get('src') or tag.get('href') or tag.get('content')
                if src and not src.startswith(parsed.scheme + '://' + parsed.netloc):
                    external_links += 1
            ratio = external_links / len(meta_links)
            if ratio < 0.17:
                return 1
            elif 0.17 <= ratio <= 0.81:
                return 0
            else:
                return -1
        except:
            return 0

    def _sfh(self, url):
        try:
            response = self._session.get(url, timeout=(1.5, self.timeout))
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            if not forms:
                return 1
            parsed = urlparse(url)
            for form in forms:
                action = form.get('action', '')
                if action == '' or action == 'about:blank':
                    return -1
                if action.startswith('#'):
                    return 0
            return 1
        except:
            return 0

    def _submitting_to_email(self, url):
        try:
            response = self._session.get(url, timeout=(1.5, self.timeout))
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if 'mailto:' in action:
                    return -1
            return 1
        except:
            return 0

    def _abnormal_url(self, url, domain):
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return -1
            hostname_parts = parsed.hostname.split('.')
            if len(hostname_parts) >= 2:
                registered = '.'.join(hostname_parts[-2:])
                if registered not in url:
                    return -1
            return 1
        except:
            return 0

    def _redirect(self, url):
        try:
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            if len(response.history) <= 1:
                return 1
            elif len(response.history) == 2:
                return 0
            else:
                return -1
        except:
            return 0

    def _on_mouseover(self, url):
        try:
            response = self._session.get(url, timeout=(1.5, self.timeout))
            if 'onmouseover' in response.text.lower():
                return -1
            return 1
        except:
            return 0

    def _right_click(self, url):
        try:
            response = self._session.get(url, timeout=(1.5, self.timeout))
            if 'event.button==2' in response.text.lower():
                return -1
            return 1
        except:
            return 0

    def _popup_window(self, url):
        try:
            response = self._session.get(url, timeout=(1.5, self.timeout))
            if 'window.open' in response.text.lower():
                return -1
            return 1
        except:
            return 0

    def _iframe(self, url):
        try:
            response = self._session.get(url, timeout=(1.5, self.timeout))
            soup = BeautifulSoup(response.text, 'html.parser')
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                if iframe.get('frameborder', '') == '0' or iframe.get('border', '') == '0':
                    return -1
            if iframes:
                return 0
            return 1
        except:
            return 0

    def _age_of_domain(self, domain):
        try:
            w = whois.whois(domain)
            if w.creation_date:
                create_date = w.creation_date
                if isinstance(create_date, list):
                    create_date = create_date[0]
                now = datetime.now()
                age = (now - create_date).days
                if age > 180:
                    return 1
                else:
                    return -1
            return 0
        except:
            return 0

    def _dns_record(self, domain):
        try:
            socket.gethostbyname(domain)
            return 1
        except:
            return -1

    def _web_traffic(self, url):
        return 0

    def _page_rank(self, url):
        return 0

    def _google_index(self, url):
        return 0

    def _links_pointing_to_page(self, url):
        return 0

    def _statistical_report(self, url):
        return 0

    @staticmethod
    def feature_description(name):
        descriptions = {
            'having_IP_Address': 'Menggunakan IP address sebagai host',
            'URL_Length': 'Panjang URL',
            'Shortining_Service': 'Menggunakan layanan pemendek URL',
            'having_At_Symbol': 'Terdapat simbol @ pada URL',
            'double_slash_redirecting': 'Terdapat // redirect dalam URL',
            'Prefix_Suffix': 'Terdapat tanda - pada domain',
            'having_Sub_Domain': 'Jumlah subdomain',
            'SSLfinal_State': 'Menggunakan HTTPS dengan sertifikat valid',
            'Domain_registeration_length': 'Masa registrasi domain',
            'favicon': 'Favicon terload dari domain eksternal',
            'port': 'Port yang digunakan',
            'HTTPS_token': 'Domain mengandung "https"',
            'Request_URL': 'Proporsi resource dari domain lain',
            'URL_of_Anchor': 'Proporsi anchor tag ke domain lain',
            'Links_in_tags': 'Proporsi link dalam tag <meta>/<script>',
            'SFH': 'Server Form Handler validity',
            'Submitting_to_email': 'Form mengirim ke email',
            'Abnormal_URL': 'URL abnormal berdasarkan hostname',
            'Redirect': 'Jumlah redirect',
            'on_mouseover': 'Status bar manipulation via onMouseOver',
            'RightClick': 'Right click disabled',
            'popUpWindow': 'Popup window',
            'Iframe': 'Penggunaan iframe',
            'age_of_domain': 'Umur domain dalam hari',
            'DNSRecord': 'DNS record tersedia',
            'web_traffic': 'Web traffic rank',
            'Page_Rank': 'Google Page Rank',
            'Google_Index': 'Terindeks di Google',
            'Links_pointing_to_page': 'Jumlah link mengarah ke halaman',
            'Statistical_report': 'Host terdaftar di laporan statistik',
        }
        return descriptions.get(name, name)

    @staticmethod
    def value_explanation(name, value):
        explanations = {
            'having_IP_Address': {1: 'Tidak menggunakan IP', -1: 'Menggunakan IP', 0: 'Tidak diketahui'},
            'URL_Length': {1: 'URL pendek (<54)', 0: 'URL sedang (54-75)', -1: 'URL panjang (>75)'},
            'Shortining_Service': {1: 'Bukan URL pendek', -1: 'URL pendek', 0: 'Tidak diketahui'},
            'having_At_Symbol': {1: 'Tidak ada @', -1: 'Ada @', 0: 'Tidak diketahui'},
            'double_slash_redirecting': {1: 'Tidak ada //', -1: 'Ada //', 0: 'Tidak diketahui'},
            'Prefix_Suffix': {1: 'Tidak ada - di domain', -1: 'Ada - di domain', 0: 'Tidak diketahui'},
            'having_Sub_Domain': {1: '1 subdomain', 0: '2 subdomain', -1: '>2 subdomain'},
            'SSLfinal_State': {1: 'HTTPS valid', 0: 'HTTPS tidak valid', -1: 'HTTP'},
            'Domain_registeration_length': {1: '>1 tahun', 0: 'Tidak diketahui', -1: '<=1 tahun'},
            'favicon': {1: 'Favicon dari domain asli', -1: 'Favicon dari domain lain', 0: 'Tidak diketahui'},
            'port': {1: 'Port standar', -1: 'Port tidak standar', 0: 'Tidak diketahui'},
            'HTTPS_token': {1: 'Domain bersih', -1: 'Ada https di domain', 0: 'Tidak diketahui'},
            'Request_URL': {1: 'Sedikit resource eksternal', 0: 'Sedang', -1: 'Banyak resource eksternal'},
            'URL_of_Anchor': {1: 'Sedikit anchor eksternal', 0: 'Sedang', -1: 'Banyak anchor eksternal'},
            'Links_in_tags': {1: 'Sedikit link eksternal', 0: 'Sedang', -1: 'Banyak link eksternal'},
            'SFH': {1: 'SFH aman', 0: 'Meragukan', -1: 'SFH mencurigakan'},
            'Submitting_to_email': {1: 'Tidak ke email', -1: 'Mengirim ke email', 0: 'Tidak diketahui'},
            'Abnormal_URL': {1: 'URL normal', 0: 'Meragukan', -1: 'URL abnormal'},
            'Redirect': {1: '<=1 redirect', 0: '2 redirect', -1: '>2 redirect'},
            'on_mouseover': {1: 'Tidak ada', -1: 'Ada onMouseOver', 0: 'Tidak diketahui'},
            'RightClick': {1: 'Tidak ada', -1: 'RightClick disabled', 0: 'Tidak diketahui'},
            'popUpWindow': {1: 'Tidak ada', -1: 'Ada popup', 0: 'Tidak diketahui'},
            'Iframe': {1: 'Tidak ada/aman', 0: 'Ada iframe', -1: 'Iframe mencurigakan'},
            'age_of_domain': {1: '>6 bulan', -1: '<=6 bulan', 0: 'Tidak diketahui'},
            'DNSRecord': {1: 'DNS valid', -1: 'DNS tidak valid', 0: 'Tidak diketahui'},
        }
        return explanations.get(name, {}).get(value, f'Nilai {value}')
