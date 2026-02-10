import socket
import concurrent.futures
from datetime import datetime
from typing import List, Tuple

class PortScanner:
    def __init__(self, target_ip: str, timeout: float = 1.0):
        """
        포트 스캐너 초기화
        
        Args:
            target_ip: 스캔할 대상 IP 주소
            timeout: 연결 타임아웃 (초)
        """
        self.target_ip = target_ip
        self.timeout = timeout
        self.open_ports = []
    
    def scan_port(self, port: int) -> Tuple[int, bool, str]:
        """
        특정 포트 스캔
        
        Args:
            port: 스캔할 포트 번호
            
        Returns:
            (포트번호, 열림여부, 서비스명) 튜플
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return (port, True, service)
            else:
                return (port, False, "")
        except socket.error:
            return (port, False, "")
    
    def scan_range(self, start_port: int, end_port: int, 
                   max_workers: int = 100) -> List[Tuple[int, str]]:
        """
        포트 범위 스캔 (멀티스레딩 사용)
        """
        self.open_ports = [] # Reset for new scan

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port, port): port 
                      for port in range(start_port, end_port + 1)}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    self.open_ports.append((port, service))
        
        return sorted(self.open_ports)
    
    def scan_specific_ports(self, ports: List[int], max_workers: int = 100) -> List[Tuple[int, str]]:
        """
        특정 포트 목록 스캔
        """
        self.open_ports = [] # Reset for new scan

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    self.open_ports.append((port, service))
        
        return sorted(self.open_ports)
