from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from scanner_core import check_vulnerability
import ipaddress
import json
import time
from malicious_link_scanner import check_malicious, expand_url, get_snapshot_url
from react2shell_scanner_core import React2ShellScanner



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
    target_input = data.get('target', '').strip()

    if not target_input:
        return jsonify({'error': 'No target IP provided'}), 400

    targets = []
    try:
        if '/' in target_input:
            network = ipaddress.ip_network(target_input, strict=False)
            if network.num_addresses > 256:
                 return jsonify({'error': 'Scan range too large. Max 256 IPs allowed.'}), 400
            targets = [str(ip) for ip in network.hosts()]
        else:
            targets = [target_input]

        def generate():
            import concurrent.futures
            total = len(targets)
            count = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_ip = {executor.submit(check_vulnerability, f"http://{ip}:7001"): ip for ip in targets}
                for future in concurrent.futures.as_completed(future_to_ip):
                    count += 1
                    ip = future_to_ip[future]
                    is_vuln, reason = future.result()
                    progress = int((count / total) * 100)
                    yield f"data: {json.dumps({'result': {'target': str(ip), 'vulnerable': is_vuln, 'reason': reason}, 'progress': progress, 'current': count, 'total': total})}\n\n"

        return Response(stream_with_context(generate()), mimetype='text/event-stream')

    except ValueError:
        return jsonify({'error': 'Invalid IP address or CIDR format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/ports', methods=['POST'])
def scan_ports():
    data = request.json
    target_input = data.get('target', '').strip()
    port_input_raw = str(data.get('ports', '1-1024')).strip()
    
    # Default to 1-1024 if empty
    if not port_input_raw:
        port_input_raw = '1-1024'
    port_input = port_input_raw

    if not target_input:
        return jsonify({'error': 'No target IP provided'}), 400

    from port_scanner_core import PortScanner
    
    try:
        if '-' in str(port_input):
            start, end = map(int, str(port_input).split('-'))
            ports = list(range(start, end + 1))
        elif ',' in str(port_input) or ' ' in str(port_input):
            ports = [int(p) for p in str(port_input).replace(',', ' ').split()]
        else:
            ports = [int(port_input)]

        targets = []
        if '/' in target_input:
            network = ipaddress.ip_network(target_input, strict=False)
            if network.num_addresses > 256:
                 return jsonify({'error': 'Scan range too large. Max 256 IPs allowed.'}), 400
            targets = [str(ip) for ip in network.hosts()]
        else:
            targets = [target_input]

        def generate():
            total_tasks = len(targets) * len(ports)
            completed_tasks = 0
            
            for target in targets:
                scanner = PortScanner(target)
                any_open = False
                any_alive = False
                for port, is_open, service, is_alive in scanner.scan_list_generator(ports):
                    completed_tasks += 1
                    progress = int((completed_tasks / total_tasks) * 100)
                    if is_alive:
                        any_alive = True
                    if is_open:
                        any_open = True
                        yield f"data: {json.dumps({'result': {'ip': target, 'port': port, 'service': service}, 'progress': progress})}\n\n"
                    else:
                        # Still yield progress even if port is closed
                        yield f"data: {json.dumps({'progress': progress})}\n\n"
                
                # If host is alive but no ports found, send a specific message
                if any_alive and not any_open:
                    yield f"data: {json.dumps({'info': f'No open ports found on {target} in range {port_input_raw}, but host is responsive.', 'progress': progress})}\n\n"

                # Signal that this target IP is done. 
                # Use has_open_ports flag (which frontend uses) to represent "is host alive/responsive"
                yield f"data: {json.dumps({'ip_done': target, 'has_open_ports': any_alive, 'progress': progress})}\n\n"
        
        return Response(stream_with_context(generate()), mimetype='text/event-stream')

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/ssl', methods=['POST'])
def scan_ssl():
    data = request.json
    target = data.get('target', '').strip()
    port = int(str(data.get('port', 443)).strip())

    if not target:
        return jsonify({'error': 'No target host provided'}), 400

    from ssl_tls_scanner_core import SSLTLSScanner
    
    try:
        scanner = SSLTLSScanner(target, int(port))
        
        def generate():
            steps = 5
            completed = 0
            for step_name, result in scanner.run_scan_generator():
                completed += 1
                progress = int((completed / steps) * 100)
                yield f"data: {json.dumps({'step': step_name, 'result': result, 'progress': progress})}\n\n"

        return Response(stream_with_context(generate()), mimetype='text/event-stream')

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/malicious', methods=['POST'])
def scan_malicious():
    data = request.json
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # 1. Expand URL (handle shorteners)
        final_url = expand_url(url)
        
        # 2. Check for malicious content
        is_malicious, reason, confidence = check_malicious(final_url)
        
        # 3. Get Snapshot URL
        snapshot_url = get_snapshot_url(final_url)
        
        return jsonify({
            'original_url': url,
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


@app.route('/api/scan/react2shell', methods=['POST'])
def scan_react2shell():
    data = request.json
    target_input = data.get('target', '').strip()

    if not target_input:
        return jsonify({'error': 'No target IP provided'}), 400

    targets = []
    try:
        if '/' in target_input:
            network = ipaddress.ip_network(target_input, strict=False)
            if network.num_addresses > 256:
                 return jsonify({'error': 'Scan range too large. Max 256 IPs allowed.'}), 400
            targets = [str(ip) for ip in network.hosts()]
        else:
            targets = [target_input]

        scanner = React2ShellScanner(targets)
        
        def generate():
            total = len(targets)
            count = 0
            for result in scanner.run_scan():
                count += 1
                progress = int((count / total) * 100)
                yield f"data: {json.dumps({'result': result, 'progress': progress, 'current': count, 'total': total})}\n\n"
        
        return Response(stream_with_context(generate()), mimetype='text/event-stream')

    except ValueError:
        return jsonify({'error': 'Invalid IP address or CIDR format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # host='0.0.0.0' allows access from other devices on the network
    app.run(host='0.0.0.0', debug=True, port=5657)
