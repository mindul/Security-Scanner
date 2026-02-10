from flask import Flask, render_template, request, jsonify
from scanner_core import check_vulnerability
import ipaddress

app = Flask(__name__)

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/scan/weblogic', methods=['POST'])
def scan_weblogic():
    data = request.json
    target_input = data.get('target')

    if not target_input:
        return jsonify({'error': 'No target provided'}), 400

    results = []

    # Handle IP Range or Single IP
    try:
        # Check if it's a CIDR block
        if '/' in target_input:
            network = ipaddress.ip_network(target_input, strict=False)
            # Limit strictly to avoid abuse/performance issues in this demo
            if network.num_addresses > 256:
                 return jsonify({'error': 'Scan range too large. Max 256 IPs allowed.'}), 400
            
            for ip in network.hosts():
                 # Assuming default port 7001 for WebLogic if not specified, 
                 # but usually scanners scan ports. For this demo, we assume http://{ip}:7001
                 # Realistically, user might input full URL or IP.
                 # Let's support http/https prefix or default to http://{ip}:7001
                 url = f"http://{ip}:7001"
                 is_vuln, reason = check_vulnerability(url)
                 results.append({
                     'target': str(ip),
                     'url': url,
                     'vulnerable': is_vuln,
                     'reason': reason
                 })
        else:
            # Single Target
            # If input doesn't start with http, assume http://{input}:7001
            if not target_input.startswith('http'):
                 url = f"http://{target_input}:7001"
            else:
                 url = target_input
            
            is_vuln, reason = check_vulnerability(url)
            results.append({
                'target': target_input,
                'url': url,
                'vulnerable': is_vuln,
                'reason': reason
            })

    except ValueError:
        return jsonify({'error': 'Invalid IP address or CIDR format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'results': results})

@app.route('/api/scan/ports', methods=['POST'])
def scan_ports():
    data = request.json
    target_ip = data.get('target')
    port_input = data.get('ports', '1-1024') # Default to common range

    if not target_ip:
        return jsonify({'error': 'No target IP provided'}), 400

    from port_scanner_core import PortScanner
    scanner = PortScanner(target_ip)
    
    open_ports = []
    try:
        if '-' in str(port_input):
            start, end = map(int, str(port_input).split('-'))
            open_ports = scanner.scan_range(start, end)
        elif ',' in str(port_input) or ' ' in str(port_input):
            # Split by comma or space
            ports = [int(p) for p in str(port_input).replace(',', ' ').split()]
            open_ports = scanner.scan_specific_ports(ports)
        else:
             # Single port
             open_ports = scanner.scan_specific_ports([int(port_input)])
             
        results = [{'port': p, 'service': s} for p, s in open_ports]
        return jsonify({'results': results})

    except ValueError:
        return jsonify({'error': 'Invalid port format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # host='0.0.0.0' allows access from other devices on the network
    app.run(host='0.0.0.0', debug=True, port=5656)
