import socket

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        
        # Send a proper HTTP request to force the server to reveal itself
        if port in [80, 443, 8000]:
            request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nAccept: */*\r\n\r\n"
            sock.send(request.encode())
            
        banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        if banner:
            lines = banner.split('\n')
            for line in lines:
                if line.lower().startswith('server:'):
                    return line.split(':', 1)[1].strip()
            return lines[0][:50] 
        return "Unknown"
    except Exception as e:
        return "No Banner"

def scan_ports(target_input):
    open_ports = []
    ports_to_test = [21, 22, 80, 443, 8000] 
    
    # 1. Explicitly resolve the hostname to an IP address
    try:
        target_ip = socket.gethostbyname(target_input)
        print(f"[*] DNS Resolution Success: {target_input} -> {target_ip}")
    except socket.gaierror:
        print(f"[!] DNS Resolution Failed for {target_input}")
        return [] # Return empty if it can't resolve the domain
    
    # 2. Run the actual scan
    for port in ports_to_test:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            print(f"[*] Testing port {port} on {target_ip}...")
            result = sock.connect_ex((target_ip, port)) 
            
            if result == 0:
                print(f"[+] Port {port} is OPEN!")
                banner = grab_banner(target_ip, port)
                open_ports.append({
                    "port": port,
                    "service": "Needs Parsing", 
                    "version": banner
                })
            sock.close()
        except socket.timeout:
            # Catch timeouts so they don't silently break the script
            print(f"[-] Port {port} timed out.")
        except Exception as e:
            print(f"[!] Socket error on port {port}: {e}")
            
    return open_ports