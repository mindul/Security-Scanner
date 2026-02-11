from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    """
    Scans the network for active devices using ARP requests.
    
    Args:
        ip_range (str): The IP range to scan (e.g., "192.168.0.1/24").
        
    Returns:
        list: A list of dictionaries containing 'ip' and 'mac' of discovered devices.
    """
    # Create ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    try:
        # Send packet and receive response
        # timeout=2 is usually sufficient for local networks
        result = srp(packet, timeout=2, verbose=False)[0]

        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        return devices
    except PermissionError:
        return {'error': 'Permission denied. Run with sudo.'}
    except Exception as e:
        return {'error': str(e)}
