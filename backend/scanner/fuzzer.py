import requests
import concurrent.futures

def check_directory(base_url, directory):
    # Construct the full URL (e.g., http://scanme.nmap.org/admin)
    url = f"http://{base_url}/{directory}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    try:
        # We use timeout=3 so we don't hang on dead pages
        response = requests.get(url, headers=headers, timeout=3)
        
        # If the server responds with 200 OK, the directory exists and is accessible
        # If it responds with 403 Forbidden, it exists but we are blocked
        if response.status_code in [200, 403]:
            return {"directory": f"/{directory}", "status": response.status_code}
    except requests.exceptions.RequestException:
        pass
    return None

def run_fuzzer(target_ip):
    # A mini-wordlist of juicy targets
    wordlist = [
        "admin", "administrator", "login", "config", "backup", 
        "test", "dev", "phpmyadmin", ".git", "api"
    ]
    
    discovered = []
    
    # We use ThreadPoolExecutor to run these requests simultaneously (making it fast)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        # Map the check_directory function to our wordlist
        futures = [executor.submit(check_directory, target_ip, word) for word in wordlist]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                discovered.append(result)
                
    return discovered