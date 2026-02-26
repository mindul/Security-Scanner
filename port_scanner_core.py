import socket
import concurrent.futures
import errno
from datetime import datetime
from typing import List, Tuple

class PortScanner:
    def __init__(self, target_ip: str, timeout: float = 1.5):
        """
        포트 스캐너 초기화
        
        Args:
            target_ip: 스캔할 대상 IP 주소
            timeout: 연결 타임아웃 (초)
        """
        self.target_ip = target_ip
        self.timeout = timeout
        self.open_ports = []
    
    def scan_port(self, port: int) -> Tuple[int, bool, str, bool]:
        """
        특정 포트 스캔
        
        Args:
            port: 스캔할 포트 번호
            
        Returns:
            (포트번호, 열림여부, 서비스명, 활성여부) 튜플
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            # If result is 0, port is open (and host is obviously alive)
            # If result is ECONNREFUSED, port is closed but host is ALIVE
            is_open = (result == 0)
            is_alive = (result == 0 or result == errno.ECONNREFUSED)
            
            if is_open:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return (port, True, service, True)
            else:
                return (port, False, "", is_alive)
        except Exception:
            return (port, False, "", False)
    
    def scan_range(self, start_port: int, end_port: int, 
                   max_workers: int = 100) -> List[Tuple[int, bool, str, bool]]:
        """
        포트 범위 스캔 (멀티스레딩 사용)
        """
        return list(self.scan_range_generator(start_port, end_port, max_workers))

    def scan_range_generator(self, start_port: int, end_port: int, 
                           max_workers: int = 100):
        """
        포트 범위 스캔 제너레이터 (멀티스레딩 사용)
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port, port): port 
                      for port in range(start_port, end_port + 1)}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, service, is_alive = future.result()
                yield (port, is_open, service, is_alive)


    
    def scan_specific_ports(self, ports: List[int], max_workers: int = 100) -> List[Tuple[int, bool, str, bool]]:
        """
        특정 포트 목록 스캔
        """
        return list(self.scan_list_generator(ports, max_workers))

    def scan_list_generator(self, ports: List[int], max_workers: int = 100):
        """
        특정 포트 목록 스캔 제너레이터
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, service, is_alive = future.result()
                yield (port, is_open, service, is_alive)


