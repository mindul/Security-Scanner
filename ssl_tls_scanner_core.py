import ssl
import socket
from datetime import datetime
from typing import Dict, List
from OpenSSL import SSL, crypto
import certifi

class SSLTLSScanner:
    def __init__(self, target_host: str, target_port: int = 443, timeout: float = 5.0):
        """
        SSL/TLS 스캐너 초기화
        
        Args:
            target_host: 스캔할 대상 호스트
            target_port: 스캔할 포트 (기본값: 443)
            timeout: 연결 타임아웃 (초)
        """
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.results = {}
        
        # 취약한 프로토콜 및 암호화 스위트
        self.weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        self.weak_ciphers = [
            'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 
            'PSK', 'SRP', 'CAMELLIA', 'IDEA', 'SEED',
            'aNULL', 'eNULL', 'EXP', 'LOW'
        ]
    
    def get_certificate_info(self) -> Dict:
        """
        SSL 인증서 정보 수집
        
        Returns:
            인증서 정보 딕셔너리
        """
        cert_info = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), 
                                         timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    
                    # OpenSSL로 상세 정보 추출
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_binary)
                    
                    # 기본 정보
                    # Decoding bytes to string for JSON serialization
                    cert_info['subject'] = {k.decode(): v.decode() for k, v in dict(x509.get_subject().get_components()).items()}
                    cert_info['issuer'] = {k.decode(): v.decode() for k, v in dict(x509.get_issuer().get_components()).items()}
                    cert_info['version'] = x509.get_version()
                    cert_info['serial_number'] = x509.get_serial_number()
                    
                    # 유효기간
                    not_before = datetime.strptime(
                        x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'
                    )
                    not_after = datetime.strptime(
                        x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'
                    )
                    
                    cert_info['valid_from'] = not_before.strftime('%Y-%m-%d %H:%M:%S')
                    cert_info['valid_until'] = not_after.strftime('%Y-%m-%d %H:%M:%S')
                    cert_info['days_remaining'] = (not_after - datetime.now()).days
                    
                    # 서명 알고리즘
                    cert_info['signature_algorithm'] = x509.get_signature_algorithm().decode('utf-8')
                    
                    # Subject Alternative Names (SAN)
                    san_list = []
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if 'subjectAltName' in str(ext.get_short_name()):
                            san_list = str(ext).split(', ')
                    cert_info['san'] = san_list
                    
                    # 키 크기
                    public_key = x509.get_pubkey()
                    cert_info['key_size'] = public_key.bits()
                    
                    # 인증서 체인 검증
                    cert_info['chain_valid'] = self.verify_certificate_chain(cert_binary)
                    
        except Exception as e:
            cert_info['error'] = str(e)
        
        return cert_info
    
    def verify_certificate_chain(self, cert_binary: bytes) -> bool:
        """
        인증서 체인 검증
        """
        try:
            context = ssl.create_default_context()
            context.load_verify_locations(certifi.where())
            
            with socket.create_connection((self.target_host, self.target_port), 
                                         timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    return True
        except ssl.SSLError:
            return False
        except Exception:
            return False
    
    def check_protocol_support(self) -> Dict[str, bool]:
        """
        지원하는 SSL/TLS 프로토콜 버전 확인
        """
        protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv23,
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1.0': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
            'TLSv1.3': ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None,
        }
        
        supported = {}
        
        for protocol_name, protocol_version in protocols.items():
            if protocol_version is None:
                supported[protocol_name] = False
                continue
            
            try:
                context = ssl.SSLContext(protocol_version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # SSLv2, SSLv3 비활성화 시도
                if protocol_name in ['SSLv2', 'SSLv3']:
                    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
                    supported[protocol_name] = False
                    continue
                
                with socket.create_connection((self.target_host, self.target_port), 
                                             timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                        supported[protocol_name] = True
            except:
                supported[protocol_name] = False
        
        return supported
    
    def get_cipher_suites(self) -> List[str]:
        """
        지원하는 암호화 스위트 목록 확인
        """
        cipher_suites = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), 
                                         timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cipher_suites.append(ssock.cipher()[0])
        except Exception as e:
            pass
        
        return cipher_suites
    
    def check_weak_ciphers(self, cipher_suites: List[str]) -> List[str]:
        """
        취약한 암호화 스위트 확인
        """
        weak_found = []
        
        for cipher in cipher_suites:
            for weak in self.weak_ciphers:
                if weak in cipher.upper():
                    weak_found.append(cipher)
                    break
        
        return weak_found
    
    def check_security_headers(self) -> Dict[str, bool]:
        """
        보안 헤더 확인 (HSTS 등)
        """
        headers = {
            'HSTS': False,
            'OCSP_Stapling': False
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), 
                                         timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    headers['OCSP_Stapling'] = hasattr(ssock, 'get_unverified_chain')
        except:
            pass
        
        return headers
    
    def analyze_vulnerabilities(self) -> List[str]:
        """
        발견된 취약점 분석
        """
        vulnerabilities = []
        
        # 인증서 관련 취약점
        cert_info = self.results.get('certificate', {})
        if 'error' in cert_info:
            vulnerabilities.append(f"[HIGH] 인증서 정보 수집 실패: {cert_info['error']}")
        else:
            if cert_info.get('days_remaining', 9999) < 0:
                vulnerabilities.append("[CRITICAL] 인증서가 만료되었습니다")
            elif cert_info.get('days_remaining', 9999) < 30:
                vulnerabilities.append(f"[HIGH] 인증서가 {cert_info['days_remaining']}일 후 만료됩니다")
            
            if not cert_info.get('chain_valid', False):
                vulnerabilities.append("[HIGH] 인증서 체인 검증 실패")
            
            if cert_info.get('key_size', 0) < 2048:
                vulnerabilities.append(f"[MEDIUM] 약한 키 크기: {cert_info.get('key_size')} bits (권장: 2048+ bits)")
            
            sig_algo = cert_info.get('signature_algorithm', '').lower()
            if 'sha1' in sig_algo or 'md5' in sig_algo:
                vulnerabilities.append(f"[HIGH] 약한 서명 알고리즘: {cert_info.get('signature_algorithm')}")
        
        # 프로토콜 관련 취약점
        protocols = self.results.get('protocols', {})
        for protocol, supported in protocols.items():
            if supported and protocol in self.weak_protocols:
                vulnerabilities.append(f"[HIGH] 취약한 프로토콜 지원: {protocol}")
        
        if not protocols.get('TLSv1.2') and not protocols.get('TLSv1.3'):
            vulnerabilities.append("[HIGH] TLS 1.2 이상 미지원")
        
        # 암호화 스위트 관련 취약점
        weak_ciphers = self.results.get('weak_ciphers', [])
        if weak_ciphers:
            for cipher in weak_ciphers:
                vulnerabilities.append(f"[MEDIUM] 약한 암호화 스위트 지원: {cipher}")
        
        return vulnerabilities
    
    def run_scan(self) -> Dict:
        """
        전체 SSL/TLS 스캔 실행
        """
        return dict(self.run_scan_generator())

    def run_scan_generator(self):
        """
        전체 SSL/TLS 스캔 실행 제너레이터
        """
        self.results['certificate'] = self.get_certificate_info()
        yield ('certificate', self.results['certificate'])
        
        self.results['protocols'] = self.check_protocol_support()
        yield ('protocols', self.results['protocols'])
        
        cipher_suites = self.get_cipher_suites()
        self.results['cipher_suites'] = cipher_suites
        self.results['weak_ciphers'] = self.check_weak_ciphers(cipher_suites)
        yield ('ciphers', {'suites': cipher_suites, 'weak': self.results['weak_ciphers']})
        
        self.results['security_features'] = self.check_security_headers()
        yield ('security_features', self.results['security_features'])
        
        self.results['vulnerabilities'] = self.analyze_vulnerabilities()
        yield ('vulnerabilities', self.results['vulnerabilities'])
        
        return self.results

