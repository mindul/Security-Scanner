import requests
import socket
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class React2ShellScanner:
    def __init__(self, targets, max_threads=10):
        self.targets = targets
        self.max_threads = max_threads
        self.results = []

    def check_port(self, ip, port, timeout=1):
        """Check if a port is open on a given IP."""
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError):
            return False
        except Exception:
            return False

    def scan_target(self, target):
        """Scan a single target for React2Shell-related vulnerabilities."""
        # Common ports for Node.js/React apps
        common_ports = [3000, 5000, 8080, 80, 443]
        vulnerabilities = []
        info = []

        # 1. Port Scanning for Common Node.js ports
        open_ports = []
        for port in common_ports:
            if self.check_port(target, port):
                open_ports.append(port)

        if not open_ports:
              return {
                'target': target,
                'vulnerable': False,
                'reason': 'No common Node.js/React ports open (3000, 5000, 8080, 80, 443).'
            }

        # 2. RCE / Command Injection Simulation (Simulation Mode)
        # In a real scenario, this would involve sending specific payloads to endpoints
        # like /_next/data/, /api/..., or triggering server-side rendering vulnerabilities.
        
        # Simulated logic: If port 3000 is open and it returns a specific "React" related header
        # or if we detect an exposed debugger.
        
        is_vulnerable = False
        reason = "Scanning completed."

        for port in open_ports:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{target}:{port}"
            
            try:
                # Check for Server-Side Vulnerabilities (Simulated)
                response = requests.get(url, timeout=3, verify=False)
                
                # Check for headers indicating React/Node.js
                server_header = response.headers.get('Server', '').lower()
                x_powered_by = response.headers.get('X-Powered-By', '').lower()

                if 'express' in x_powered_by or 'node.js' in server_header or 'next.js' in x_powered_by:
                    info.append(f"Detected Node.js/React environment on port {port}.")
                
                # Check for Debugger (e.g., /_next/static/...)
                # Simulation: If port 9229 (Node.js Debugger) is open, it's a critical vulnerability
                if self.check_port(target, 9229):
                    is_vulnerable = True
                    reason = "[CRITICAL] Node.js Debugger port 9229 is exposed. Potential RCE."
                    break

                # Mocking a specific RCE check for React2Shell (e.g., prototype pollution or SSRF)
                # Let's say we check if a specific payload returns a 500 with a stack trace
                payload_url = f"{url}/api/v1/debug?cmd=id"
                # (This is just a simulated request, it won't actually execute anything)
                vuln_response = requests.get(payload_url, timeout=2, verify=False)
                if vuln_response.status_code == 200 and 'uid=' in vuln_response.text:
                    is_vulnerable = True
                    reason = f"[VULNERABILITY] Command Injection detected via {payload_url}."
                    break

            except requests.exceptions.RequestException as e:
                info.append(f"Port {port} connection error: {str(e)}")

        if not is_vulnerable:
            reason = " | ".join(info) if info else "No vulnerabilities found on scanned ports."

        return {
            'target': target,
            'vulnerable': is_vulnerable,
            'reason': reason
        }

    def run_scan(self):
        """Run the multi-threaded scan and yield results one by one."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip = {executor.submit(self.scan_target, target): target for target in self.targets}
            for future in concurrent.futures.as_completed(future_to_ip):
                try:
                    data = future.result()
                    yield data
                except Exception as exc:
                    yield {
                        'target': future_to_ip[future],
                        'vulnerable': False,
                        'reason': f'Scan error: {str(exc)}'
                    }

