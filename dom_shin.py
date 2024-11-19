#https://github.com/Jenderal92/check-expired-aged-domain/

import whois
import socket
from datetime import datetime
from queue import Queue
from threading import Thread

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

def extract_domain(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain and '.' in domain:
        return domain.lower()
    return None

def check_dns(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

def check_domain(domain, result_queue, expired_domains, aged_domains):
    try:
        domain_info = whois.whois(domain)
        if domain_info.domain_name is None:
            print("{} not found, dianggap sebagai domain expired.".format(domain))
            if not check_dns(domain):
                result_queue.put(domain)
                if domain not in expired_domains:
                    expired_domains.add(domain)
                    with open("expired.txt", "a") as file:
                        file.write("{}\n".format(domain))
            return

        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date

        if isinstance(domain_info.expiration_date, list):
            expiration_date = domain_info.expiration_date[0]
        else:
            expiration_date = domain_info.expiration_date

        if expiration_date and isinstance(expiration_date, str):
            try:
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except ValueError:
                print("Format tanggal kedaluwarsa tidak valid untuk {}".format(domain))
                expiration_date = None

        if creation_date:
            age = (datetime.now() - creation_date).days // 365
            print("Nama domain: {}".format(domain_info.domain_name))
            print("Tanggal Pembuatan: {}".format(creation_date))
            print("Tanggal Kedaluwarsa: {}".format(expiration_date))
            print("Umur Domain: {} tahun".format(age))
            print("Status: {}".format(domain_info.status))

        if expiration_date and expiration_date < datetime.now() and age >= 5:
            if not check_dns(domain):
                if domain not in aged_domains:
                    aged_domains.add(domain)
                    with open("aged.txt", "a") as file:
                        file.write("{} - Umur: {} tahun\n".format(domain, age))
        if expiration_date and expiration_date < datetime.now():
            if not check_dns(domain):
                if domain not in expired_domains:
                    expired_domains.add(domain)
                    with open("expired.txt", "a") as file:
                        file.write("{}\n".format(domain))

    except Exception as e:
        print("Error pada {}: {}".format(domain, str(e)))
        if "No match for" in str(e) or "NOT FOUND" in str(e).upper():
            if not check_dns(domain):
                if domain not in expired_domains:
                    expired_domains.add(domain)
                    with open("expired.txt", "a") as file:
                        file.write("{}\n".format(domain))

    result_queue.put(domain)

def worker(domain_queue, result_queue, expired_domains, aged_domains):
    while not domain_queue.empty():
        domain = domain_queue.get()
        check_domain(domain, result_queue, expired_domains, aged_domains)
        domain_queue.task_done()

if __name__ == "__main__":
    try:
        print('Check Expired And aged domain | Shin Code\n')
        domainmu = input("DOMAIN LIST : ")
        THREAD = input("THREAD : ")
        with open(domainmu, "r") as f:
            domain_list = {line.strip() for line in f if line.strip()}
    except Exception as e:
        print("Error membaca file domains.txt: {}".format(str(e)))
        exit()

    valid_domain_set = set()
    for url in domain_list:
        domain = extract_domain(url)
        if domain: 
            valid_domain_set.add(domain)

    domain_queue = Queue()
    result_queue = Queue()
    expired_domains = set()  
    aged_domains = set()  

    for domain in valid_domain_set:
        domain_queue.put(domain)

    num_threads = int(THREAD)
    for _ in range(num_threads):
        t = Thread(target=worker, args=(domain_queue, result_queue, expired_domains, aged_domains))
        t.daemon = True
        t.start()

    domain_queue.join()

    print("Pemeriksaan domain selesai.")
