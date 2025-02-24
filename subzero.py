import re
import requests
import socket
import concurrent.futures
import argparse
from colorama import Fore, Style, init
import time
import sys
import urllib.parse
from urllib.parse import urlparse
import random
import hashlib

API_KEY = ''
ALL_Alive_Subdomains = set()

init(autoreset=True)

LOGO = rf'''{Fore.BLUE}

     .oooooo..o              .o8        oooooooooooo                              
    d8P'    `Y8             "888       d'""""""d888'                              
    Y88bo.      oooo  oooo   888oooo.        .888P    .ooooo.  oooo d8b  .ooooo.  
     `"Y8888o.  `888  `888   d88' `88b      d888'    d88' `88b `888""8P d88' `88b 
         `"Y88b  888   888   888   888    .888P      888ooo888  888     888   888 
    oo     .d8P  888   888   888   888   d888'    .P 888    .o  888     888   888 
    8""88888P'   `V88V"V8P'  `Y8bod8P' .8888888888P  `Y8bod8P' d888b    `Y8bod8P'
{Style.RESET_ALL}'''


def is_host_alive(host):
    """Проверяет доступность хоста по HTTP/HTTPS"""
    try:
        response = requests.get(f"http://{host}", timeout=10)
        return response.status_code in [200, 302, 401, 403, 405, 407, 423]  # Проверяем 20x или 30x
    except requests.RequestException:
        return False



def Parser_Status_Code(status_code):
    if not status_code:
        return {200}  # Значение по умолчанию
    try:
        return set(map(int, status_code.split(',')))
    except ValueError:
        print("[ERROR] Incorrect values of status code")
        return {200}


"""DNSDumpster"""
def get_unique_hosts(domain):
    """Получает поддомены через API и проверяет их доступность."""
    url = f'https://api.dnsdumpster.com/domain/{domain}'
    headers = {'X-API-Key': API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        api_response = response.json()
    except requests.RequestException as e:
        print(f"[ERROR] Ошибка запроса: {e}")
        return {}

    host_ip_map = {}
    for record in api_response.get("a", []):
        host = record.get("host")
        if is_host_alive(host):
            ALL_Alive_Subdomains.add(host)
    print(f'[+] Извлечено поддоменов из DnsDumpster: {len(ALL_Alive_Subdomains)}')
    return host_ip_map


def req(url, cookies=None):
    """Отправляет GET-запрос и возвращает текст ответа"""
    try:
        response = requests.get(url, headers=HEADERS, timeout=10, cookies=cookies or {})
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"[ERROR] Ошибка запроса {url}: {e}")
        return None


def fetch_ssl_certificates(domain):
    """Запрашивает SSL-сертификаты с crt.sh"""
    return req(f'https://crt.sh/?q=%25.{domain}')


def extract_ssl_subdomains(domain):
    """Извлекает поддомены из SSL-сертификатов"""
    response_text = fetch_ssl_certificates(domain)
    if not response_text:
        return set()

    subdomains = set(re.findall(r'<TD>([\w.-]+)</TD>', response_text))
    subdomains = {sub for sub in subdomains if sub.endswith(domain) and '*' not in sub}

    ALL_Alive_Subdomains.update(subdomains)
    print(f"[+] Извлечено поддоменов из Crt.sh: {len(subdomains)}")
    return subdomains


HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

def get_cookies(headers):
    """Создаёт cookies для обхода защиты Netcraft"""
    cookie = headers.get('set-cookie', '')
    if not cookie:
        return {}

    key, value = cookie.split(";", 1)[0].split("=")
    return {key: value,
            'netcraft_js_verification_response': hashlib.sha1(urllib.parse.unquote(value).encode('utf-8')).hexdigest()}

def extract_netcraft_subdomains(domain):
    """Извлекает поддомены через Netcraft"""
    base_url = f'https://searchdns.netcraft.com/?restriction=site+contains&host=.{domain}'
    subdomains = set()

    response_text = req(base_url)
    if not response_text:
        return subdomains

    cookies = get_cookies(requests.head(base_url, headers=HEADERS).headers)

    while response_text:
        new_subs = {
            urlparse(link).netloc
            for link in re.findall(r'<a class="results-table__host" href="(.*?)"', response_text)
            if link.endswith(domain)
        }

        subdomains.update(new_subs)
        ALL_Alive_Subdomains.update(new_subs)

        next_page_match = re.search(r'<a.*?href="(.*?)">Next Page', response_text)
        if not next_page_match:
            break

        time.sleep(random.uniform(5, 10))
        response_text = req(f'http://searchdns.netcraft.com{next_page_match.group(1)}', cookies)

    print(f"[+] Извлечено поддоменов из Netcraft: {len(subdomains)}")
    print('-' * 50)

    return subdomains


def extract_all_subdomains(path=None):
    """Выводит найденные живые поддомены в консоль и файл"""
    if not ALL_Alive_Subdomains:
        print(f"{Fore.RED}[INFO]{Style.RESET_ALL} Живые хосты не найдены.")
        return

    print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Найденные живые хосты:")
    for subdomain in ALL_Alive_Subdomains:
        print(f"https://{subdomain}")

    if path:
        try:
            with open(path, "w") as output:
                for subdomain in ALL_Alive_Subdomains:
                    output.write(subdomain + "\n")
            print(f"[+] Результат сохранён в: {path}")
        except Exception as e:
            print(f"[ERROR] Ошибка записи в {path}: {e}")


def start_sub_brute(domain, sub, path=None, timO=None, allowed_status_code=None):
    """Активный перебор поддоменов"""
    if allowed_status_code is None:
        allowed_status_code = {200}
    if isinstance(allowed_status_code, int):
        allowed_status_code = {allowed_status_code}  # Приводим к множеству

    url = f"http://{sub}.{domain}"
    try:
        response = requests.get(url, timeout=int(timO), allow_redirects=False)
        if response.status_code in allowed_status_code:
            print(f"\n{Fore.RED}[FOUND]{Style.RESET_ALL} {url} - Status code: {response.status_code}")
            with open(path, "a") as sub_file:
                sub_file.write(f"{url} - Status Code:{response.status_code}\n")
    except requests.ConnectionError:
        pass


def measure_time(func, *args):
    """Измеряет и выводит время выполнения функции"""
    start_time = time.time()
    func(*args)
    elapsed_time = time.time() - start_time
    print('-' * 50)
    print(f"\n{Fore.GREEN}Scan completed in {int(elapsed_time // 60)} minutes and {int(elapsed_time % 60)} seconds{Style.RESET_ALL}")


def parse_args():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(description="SubZero - Python Subdomain Scanner: Passive & Active modes")
    parser.add_argument("host", type=str, help="Target domain (e.g., example.com)")
    parser.add_argument("-type", "--type-scan", choices=["1", "2"], required=True,
                        help="'-type 1' for Passive scan, '-type 2' for Active scan")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Max concurrent connections (default: 50)")
    parser.add_argument("-i", "--input", type=str, help="Path to subdomains file (for Active scan)")
    parser.add_argument("-o", "--output", type=str, help="File to save scan results")
    parser.add_argument("-time", "--timeout", type=int, default=10, help="Timeout for requests (default: 5s)")
    parser.add_argument("-sc", "--status-code", type=str, help="Comma-separated status codes: e.g., 200,301,404 (default: 200)")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.host:
        print("[ERROR] Необходимо указать домен.")
        sys.exit(1)

    allowed_status_code = Parser_Status_Code(args.status_code) if args.status_code else {200}

    if args.type_scan == "1":
        print(LOGO)
        print("[*] Running Passive Scan...\n" + "-" * 50)
        measure_time(lambda: (get_unique_hosts(args.host),
                              extract_ssl_subdomains(args.host),
                              extract_netcraft_subdomains(args.host),
                              extract_all_subdomains(args.output)))

    elif args.type_scan == "2":
        print(LOGO)
        print("[*] Running Active Scan...\n" + "-" * 50)

        if not args.input:
            print("[ERROR] Для активного сканирования укажите файл с поддоменами (-i subdomains.txt).")
            sys.exit(1)

        try:
            with open(args.input, "r") as file:
                subdoms = file.read().splitlines()
                if not subdoms:
                    raise ValueError("[ERROR] Файл поддоменов пуст.")
        except (FileNotFoundError, ValueError) as e:
            print(e)
            sys.exit(1)

        measure_time(lambda: run_active_scan(args.host, subdoms, args.output, args.timeout, args.threads, allowed_status_code))

    else:
        print("[ERROR] Invalid scanning type. Use '--type-scan 1' or '--type-scan 2'.")
        sys.exit(1)

def run_active_scan(domain, subdomains, output, timeout, threads, allowed_status_code):
    """Запуск активного сканирования в многопоточной среде"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(start_sub_brute, domain, sub, output, timeout, allowed_status_code) for sub in subdomains]
        concurrent.futures.wait(futures)


if __name__ == "__main__":
    main()


