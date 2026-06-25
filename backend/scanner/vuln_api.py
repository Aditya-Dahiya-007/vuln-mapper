import requests
import re

def clean_banner_for_api(raw_banner):
    if not raw_banner:
        return ""
        
    # 1. Convert to lowercase to make parsing predictable
    cleaned = raw_banner.lower()
    
    # 2. Remove anything inside parentheses (e.g., "(ubuntu)", "(debian)", "(win32)")
    cleaned = re.sub(r'\(.*\)', '', cleaned)
    
    # 3. Replace slashes, underscores, and dashes with spaces
    cleaned = re.sub(r'[/_-]', ' ', cleaned)
    
    # 4. Remove common distros or noise words that confuse the NVD keyword search
    noise_words = ['ubuntu', 'debian', 'centos', 'redhat', 'linux', 'win32', 'windows']
    for word in noise_words:
        cleaned = cleaned.replace(word, '')
        
    # 5. Clean up extra whitespaces
    cleaned = ' '.join(cleaned.split())
    
    return cleaned

def check_cve(service_banner):
    if not service_banner or service_banner in ["Unknown", "No Banner", "HTTP/1.1 200 OK"]:
        return []

    # Run the raw banner through our new sanitation pipeline
    search_term = clean_banner_for_api(service_banner)
    
    # If cleaning emptied the string, stop
    if not search_term:
        return []
        
    # Hit the live NVD API with our clean keyword
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            results = []
            vulnerabilities = data.get('vulnerabilities', [])[:3]
            
            for item in vulnerabilities:
                cve_id = item.get('cve', {}).get('id', 'Unknown CVE')
                
                # Try to extract the description summary
                descriptions = item.get('cve', {}).get('descriptions', [])
                summary = descriptions[0].get('value', 'No description available.')[:100] + "..." if descriptions else "No description."
                
                results.append({
                    "cve_id": cve_id,
                    "summary": summary
                })
            return results
    except requests.exceptions.RequestException:
        return [{"error": "API Connection Failed"}]
        
    return []