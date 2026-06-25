from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from scanner.recon import scan_ports
from scanner.vuln_api import check_cve
from scanner.fuzzer import run_fuzzer

app = FastAPI()

# 1. Define your API routes FIRST
@app.get("/api/scan")
def run_scan(target: str):
    # 0. Sanitize the input to prevent socket crashes
    # This strips http://, https://, and drops any trailing paths like /admin
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].strip()
    
    # 1. Run Recon using the sanitized target
    ports = scan_ports(clean_target)
    
    # 2. Check for Vulns
    recon_results = []
    is_web_server = False 
    
    for p in ports:
        raw_banner = p.get("version", "")
        vulns = check_cve(raw_banner) 
        
        # Check if the port is a typical web port to trigger the fuzzer
        if p.get("port") in [80, 443, 8000]:
            is_web_server = True
            
        recon_results.append({
            "port": p.get("port"),
            "service_banner": raw_banner,
            "vulnerabilities": vulns
        })
        
    # 3. Run the Fuzzer if it is a web server
    hidden_directories = []
    if is_web_server:
        hidden_directories = run_fuzzer(clean_target)
        
    # Return the clean_target so the frontend displays the sanitized name
    return {
        "target": clean_target, 
        "recon": recon_results,
        "directories": hidden_directories
    }

# 2. Mount the frontend LAST
app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")