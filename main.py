import json
import requests
import time
import configparser
import threading
import os
import socket
import dns.resolver
import whois
from colorama import init, Fore

init(autoreset=True)  # Inisialisasi colorama untuk pewarnaan output CLI

def load_services(config_path):
    with open(config_path, 'r') as file:
        data = json.load(file)
    return data

def load_dns_providers(config_path):
    with open(config_path, 'r') as file:
        data = json.load(file)
    return data.get("dns_providers", {})

def load_config():
    config = configparser.ConfigParser()
    config.read("config.cfg")
    return {
        "threads": config.getint("CONFIG", "THREADS"),
        "timeout": config.getint("CONFIG", "TIMEOUT")
    }

def get_rdap_url(services, tld):
    for service in services.get("services", []):
        if tld in service[0]:
            return service[1][0]
    return None

def save_to_file(provider, domain):
    folder = "hasil"
    if not os.path.exists(folder):
    	os.makedirs(folder)
    os.makedirs(folder, exist_ok=True)
    filename = os.path.join(folder, f"{provider.upper()}.txt")
    with open(filename, "a") as file:
        file.write(f"{domain}\n")

def save_unknown(domain, nameservers, status, registration, expiration):
    with open("hasil/bad-takeover.txt", "a") as file:
        file.write(f"[*]Domain: {domain}\n[*]NS: {', '.join(ns.lower() for ns in nameservers)}\n[*]Status: {status}\n[*]Registered: {registration}\n[*]Expiration: {expiration}\n\n")

def save_live_domain(domain):
    with open("hasil/domain-hidup.txt", "a") as file:
        file.write(f"{domain}\n")

def is_domain_resolved(domain, index, total_domains):
    try:
        ip = socket.gethostbyname(domain)
        print(f"{Fore.RED}[{index}/{total_domains}][IP/HOSTED]{Fore.RESET}{Fore.WHITE}[{domain}]{Fore.RESET}{Fore.BLUE}[{ip}]")
        save_live_domain(domain)
        return True
    except socket.gaierror:
        return False

def check_dns(domain, dns_providers, index, total_domains):
    try:
        whois_data = whois.whois(domain)
        nameservers = [ns.lower() for ns in whois_data.name_servers] if whois_data.name_servers else []
        status = ", ".join(whois_data.status) if whois_data.status else "Unknown"
        registration = whois_data.creation_date if whois_data.creation_date else "Unknown"
        expiration = whois_data.expiration_date if whois_data.expiration_date else "Unknown"
        if "hold" in status.lower():
            print(f"{Fore.YELLOW}[{index}/{total_domains}][Status : Client HOLD]{Fore.RESET}{Fore.WHITE}[{domain}]{Fore.RESET}{Fore.CYAN}[{', '.join(nameservers)}]{Fore.RESET}{Fore.BLUE}[WHOIS]")
            save_unknown(domain, nameservers, status, registration, expiration)
            return
        matched = False
        for provider, ns in dns_providers.items():
            if ns.lower() in nameservers:
                # Tambahkan kondisi untuk Niagahoster
                if provider.upper() == "NIAGAHOSTER" and status.lower() != "active":
                    print(f"{Fore.YELLOW}[{index}/{total_domains}][BAD {provider.upper()}]{Fore.RESET}{Fore.WHITE}[{domain}]{Fore.RESET}{Fore.CYAN}[{', '.join(nameservers)}]{Fore.RESET}{Fore.BLUE}[WHOIS]")
                    save_unknown(domain, nameservers, status, registration, expiration)
                else:
                    print(f"{Fore.GREEN}[{index}/{total_domains}][{provider.upper()}]{Fore.RESET}{Fore.WHITE}[{domain}]{Fore.RESET}{Fore.BLUE}[WHOIS]")
                    save_to_file(provider, domain)
                matched = True
                break
        if not matched:
            print(f"{Fore.YELLOW}[{index}/{total_domains}][UNKNOWN]{Fore.RESET}{Fore.WHITE}[{domain}]{Fore.RESET}{Fore.CYAN}[{', '.join(nameservers)}]{Fore.RESET}{Fore.BLUE}[WHOIS]")
            save_unknown(domain, nameservers, status, registration, expiration)
    except Exception as e:
        print(f"{Fore.RED}Error retrieving WHOIS data for {domain}: {e}{Fore.RESET}")

def check_domain_status(domain, services, config, dns_providers, index, total_domains):
    tld = domain.split('.')[-1]
    rdap_base_url = get_rdap_url(services, tld)
    
    if not rdap_base_url:
        check_dns(domain, dns_providers, index, total_domains)
        return
    
    rdap_url = f"{rdap_base_url}domain/{domain}"
    for attempt in range(3):
        try:
            response = requests.get(rdap_url, timeout=config["timeout"])
            response.raise_for_status()
            data = response.json()
            
            nameservers = [ns.get("ldhName").lower() for ns in data.get("nameservers", [])]
            status = ", ".join(data.get("status", ["Unknown"]))
            
            registration = next((event["eventDate"] for event in data.get("events", []) if event["eventAction"] == "registration"), "Unknown")
            expiration = next((event["eventDate"] for event in data.get("events", []) if event["eventAction"] == "expiration"), "Unknown")

            if "hold" in status.lower():
                print(f"{Fore.YELLOW}[{index}/{total_domains}][Status : Client HOLD]{Fore.RESET}{Fore.WHITE}[{domain}]{Fore.RESET}{Fore.CYAN}[{', '.join(nameservers)}]{Fore.RESET}{Fore.BLUE}[RDAP {tld.upper()}]")
                save_unknown(domain, nameservers, status, registration, expiration)
                return
            
            matched = False
            for provider, ns in dns_providers.items():
                if ns.lower() in nameservers:
                    # Tambahkan kondisi untuk Niagahoster
                    if provider.upper() == "NIAGAHOSTER" and status.lower() != "active":
                        print(f"{Fore.YELLOW}[{index}/{total_domains}][BAD {provider.upper()}]{Fore.RESET}{Fore.WHITE}[{domain}]{Fore.RESET}{Fore.CYAN}[{', '.join(nameservers)}]{Fore.RESET}{Fore.BLUE}[RDAP {tld.upper()}]")
                        save_unknown(domain, nameservers, status, registration, expiration)
                    else:
                        print(f"{Fore.GREEN}[{index}/{total_domains}][{provider.upper()}]{Fore.RESET}{Fore.WHITE}[{domain}]{Fore.RESET}{Fore.BLUE}[RDAP {tld.upper()}]")
                        save_to_file(provider, domain)
                    matched = True
                    break
            
            if not matched:
                print(f"{Fore.YELLOW}[{index}/{total_domains}][UNKNOWN]{Fore.RESET}{Fore.WHITE}[{domain}]{Fore.RESET}{Fore.CYAN}[{', '.join(nameservers)}]{Fore.RESET}{Fore.BLUE}[RDAP {tld.upper()}]")
                save_unknown(domain, nameservers, status, registration, expiration)
            return
        except requests.RequestException:
            print(f"{Fore.BLUE}[{index}/{total_domains}][RETRY {attempt + 1}]{Fore.RESET}{Fore.WHITE}[{domain}]{Fore.RESET}{Fore.CYAN} Mengulang")
            if attempt < 2:
                time.sleep(config["timeout"])

def run_checks(domains, services, config, dns_providers):
    threads = []
    total_domains = len(domains)
    for index, domain in enumerate(domains, start=1):
        if is_domain_resolved(domain, index, total_domains):
            continue
        
        thread = threading.Thread(target=check_domain_status, args=(domain, services, config, dns_providers, index, total_domains))
        threads.append(thread)
        thread.start()
        if len(threads) >= config["threads"]:
            for t in threads:
                t.join()
            threads = []
    
    for t in threads:
        t.join()

if __name__ == "__main__":
    config = load_config()
    services = load_services("services.json")
    dns_providers = load_dns_providers("dns_providers.json")
    domain_input = input("Give me site list : ")
    
    try:
        with open(domain_input, "r") as file:
            domains = [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print("File tidak ditemukan. Pastikan file list.txt ada di direktori yang benar.")
        exit(1)
    
    run_checks(domains, services, config, dns_providers)
