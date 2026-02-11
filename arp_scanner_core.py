import ipaddress
from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    """
    Scans the network for active devices using ARP requests.
    Returns all IPs in the range, marking inactive ones as N/A.
    """
    try:
        # Create ARP request packet
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        # Send packet and receive response
        result = srp(packet, timeout=2, verbose=False)[0]

        # Map found devices
        found_devices = {}
        for sent, received in result:
            found_devices[received.psrc] = received.hwsrc

        # Generate list of all IPs in range
        # strict=False allows passing host bits (e.g. 192.168.1.5/24)
        network = ipaddress.ip_network(ip_range, strict=False)
        
        devices = []
        for ip in network.hosts():
            ip_str = str(ip)
            # Ensure mac is string
            mac = str(found_devices.get(ip_str, "N/A"))
            devices.append({'ip': ip_str, 'mac': mac})

        return devices

    except PermissionError:
        return {'error': 'Permission denied. Run with sudo.'}
    except ValueError as e:
         return {'error': f'Invalid IP range: {str(e)}'}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {'error': f'Scan error: {str(e)}'}
