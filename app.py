from flask import Flask, render_template, request, jsonify
from scanner_core import check_vulnerability
import ipaddress
from malicious_link_scanner import check_malicious, expand_url, get_snapshot_url

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
    target_input = data.get('target')
    port_input = data.get('ports', '1-1024') # Default to common range

    if not target_input:
        return jsonify({'error': 'No target IP provided'}), 400

    from port_scanner_core import PortScanner
    
    all_results = []
    try:
        # Parse port arguments once to optimize and error check early
        scan_mode = 'range'
        scan_args = []
        
        if '-' in str(port_input):
            start, end = map(int, str(port_input).split('-'))
            scan_mode = 'range'
            scan_args = [start, end]
        elif ',' in str(port_input) or ' ' in str(port_input):
            ports = [int(p) for p in str(port_input).replace(',', ' ').split()]
            scan_mode = 'list'
            scan_args = [ports]
        else:
             scan_mode = 'list'
             scan_args = [[int(port_input)]]

        # Parse targets (Single IP or CIDR)
        targets = []
        if '/' in target_input:
            network = ipaddress.ip_network(target_input, strict=False)
            if network.num_addresses > 256:
                 return jsonify({'error': 'Scan range too large. Max 256 IPs allowed.'}), 400
            targets = [str(ip) for ip in network.hosts()]
        else:
            targets = [target_input]

        # Scan each target
        for target in targets:
            scanner = PortScanner(target)
            open_ports = []
            
            if scan_mode == 'range':
                open_ports = scanner.scan_range(*scan_args)
            else:
                open_ports = scanner.scan_specific_ports(*scan_args)
            
            for p, s in open_ports:
                all_results.append({'ip': target, 'port': p, 'service': s})
             
        return jsonify({'results': all_results})

    except ValueError:
        return jsonify({'error': 'Invalid IP address or Port format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/malicious', methods=['POST'])
def scan_malicious():
    data = request.json
    target_url = data.get('url')

    if not target_url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        # 1. Expand URL (handle shorteners)
        final_url = expand_url(target_url)
        
        # 2. Check for malicious content
        is_malicious, reason, confidence = check_malicious(final_url)
        
        # 3. Get Snapshot URL
        snapshot_url = get_snapshot_url(final_url)
        
        return jsonify({
            'original_url': target_url,
            'final_url': final_url,
            'is_malicious': is_malicious,
            'reason': reason,
            'confidence': confidence,
            'snapshot_url': snapshot_url
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/arp', methods=['POST'])
def scan_arp():
    import traceback
    try:
        data = request.json
        target_range = data.get('target')

        if not target_range:
            return jsonify({'error': 'No target IP range provided'}), 400

        # Import inside try block to catch import errors
        from arp_scanner_core import scan_network
    
        # Perform ARP Scan
        print(f"Starting ARP scan for {target_range}")
        results = scan_network(target_range)
        
        if isinstance(results, dict) and 'error' in results:
             print(f"ARP Scan Error: {results['error']}")
             return jsonify({'error': results['error']}), 500

        return jsonify({'results': results})

    except Exception as e:
        print("Exception in scan_arp:")
        traceback.print_exc()
        return jsonify({'error': f"Internal Server Error: {str(e)}"}), 500

if __name__ == '__main__':
    # host='0.0.0.0' allows access from other devices on the network
    app.run(host='0.0.0.0', debug=True, port=5657)
