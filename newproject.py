import nmap

scanner = nmap.PortScanner()

print("Welcome to Nmap - Simple Automation Tool")
print("<-------------------------------------->")

ip_addr = input("Please enter the IP address you want to scan: ").strip()
print("The IP you entered is:", ip_addr)

resp = input("""
Please enter the type of scan you want to run:
    1) SYN ACK SCAN
    2) UDP SCAN
    3) COMPREHENSIVE SCAN
Choice: """)

print("You have selected option:", resp)

if resp == '1': 
    print("Nmap version:", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP status:", scanner[ip_addr].state())
    print("Protocols found:", scanner[ip_addr].all_protocols())
    if 'tcp' in scanner[ip_addr]:
        print("Open TCP ports:", scanner[ip_addr]['tcp'].keys())

elif resp == '2':
    print("Nmap version:", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP status:", scanner[ip_addr].state())
    print("Protocols found:", scanner[ip_addr].all_protocols())
    if 'udp' in scanner[ip_addr]:
        print("Open UDP ports:", scanner[ip_addr]['udp'].keys())

elif resp == '3':
    print("Nmap version:", scanner.nmap_version())
    scanner.scan(ip_addr, '1-65535', '-sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP status:", scanner[ip_addr].state())
    print("Protocols found:", scanner[ip_addr].all_protocols())
    if 'tcp' in scanner[ip_addr]:
        print("Open TCP ports:", scanner[ip_addr]['tcp'].keys())

else:
    print("Invalid selection. Please enter 1, 2, or 3.")

  