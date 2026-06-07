TwinGuard: Local Evil Twin Detection Dashboard
> 지금 연결된 Wi-Fi가 정말 안전한지 확인하기 위한 로컬 기반 Evil Twin 탐지 시스템입니다.
TwinGuard는 네트워크 패킷 분석과 머신러닝 탐지 결과를 결합해, 가짜 Wi-Fi 공격인 Evil Twin 공격 의심 신호를 사용자에게 직관적으로 보여주는 보안 대시보드입니다.
---
1. TwinGuard란 무엇인가요?
TwinGuard는 사용자가 복잡한 보안 지식 없이도 현재 Wi-Fi 환경이 안전한지 확인할 수 있도록 만든 로컬 보안 프로그램입니다.
프로그램은 현재 네트워크 통신을 수집하고, RSSI, RTT, BSSID 변화 여부 같은 특징을 분석한 뒤, SVM 기반 머신러닝 모델을 통해 정상 또는 위험 여부를 판단합니다.
사용자는 웹 UI에서 `보호 시작` 버튼을 누르기만 하면 됩니다.  
결과는 `정상`, `측정 중`, `위험`처럼 이해하기 쉬운 상태로 표시됩니다.
---
2. 개발 동기
Evil Twin 공격은 공격자가 정상 Wi-Fi와 비슷한 이름의 가짜 AP를 만들어 사용자의 접속을 유도하는 공격입니다.
하지만 일반 사용자가 이런 공격을 직접 구분하기는 어렵습니다.  
패킷을 분석하거나, BSSID 변화를 확인하거나, 네트워크 지연 패턴을 해석하는 일은 대부분 전문가 영역에 가깝습니다.
TwinGuard의 목표는 이 과정을 자동화하고, 누구나 사용할 수 있는 UI로 제공하는 것입니다.
즉, TwinGuard는 다음 문제를 해결하고자 합니다.
사용자가 직접 패킷을 분석하지 않아도 되게 하기
전문가가 아니어도 손쉽게 사용할 수 있기
복잡한 수치 대신 직관적인 UI로 결과를 보여주기
로컬 환경에서 독립적으로 실행되게 하기
---
3. 최신 모듈 구조
TwinGuard는 여러 Python 모듈을 실행하고, 로컬 UDP 소켓으로 데이터를 전달하는 구조입니다.
모든 통신은 `127.0.0.1` 로컬 루프백에서 이루어집니다.
단계	파일명	역할	입력	출력
1	`PacketCapture.py`	실시간 패킷 캡처 및 Wi-Fi 정보 수집	네트워크 인터페이스	UDP `5001`
2	`Preprocessor.py`	패킷 데이터 전처리 및 특징 추출	UDP `5001`	UDP `5002`
3	`SVM_deploy.py`	SVM 모델 기반 실시간 탐지	UDP `5002`	UDP `5003`
4	`ui.py`	Flask 웹 UI, 프로세스 실행/중지 관리, 결과 표시	UDP `5003`	웹 대시보드
탐지 결과 형식
최신 `SVM_deploy.py`는 복잡한 JSON이 아니라 단순 문자열 토큰을 전송합니다.
토큰	의미
`"1"`	정상, NORMAL
`"0"`	공격 의심, HIGH RISK
`ui.py`는 UDP `5003`에서 이 값을 수신하고, 웹 화면에 최신 탐지 결과를 표시합니다.
---
4. 필수 준비 사항
4.1 Python
Python 3.x가 필요합니다.
설치 시 아래 옵션을 체크하는 것을 권장합니다.
```text
Add Python to PATH
```
설치 확인:
```bash
python --version
pip --version
```
---
4.2 Wireshark, TShark, Npcap
TwinGuard는 `pyshark`를 통해 패킷을 캡처합니다.  
`pyshark`는 내부적으로 Wireshark의 `TShark`를 사용합니다.
따라서 아래 항목이 필요합니다.
Wireshark
TShark
Npcap
Wireshark 설치 중 아래 옵션을 체크하는 것을 권장합니다.
https://www.wireshark.org/download.html
설치 확인:
```bash
tshark -v
```
만약 `tshark` 명령어가 인식되지 않으면 Wireshark 설치 경로가 PATH에 등록되어 있는지 확인해야 합니다.
---
5. 설치 방법
5.1 프로젝트 클론
```bash
git clone https://github.com/DeceptiveRat/TwinGuard.git
```
---
5.2 필수 Python 패키지 설치
```bash
python -m pip install flask pyshark pandas numpy scikit-learn joblib
```
각 패키지 역할은 다음과 같습니다.
패키지	역할
`flask`	웹 UI 서버 실행
`pyshark`	패킷 캡처 및 TShark 연동
`pandas`	모델 입력 데이터를 표 형태로 변환
`numpy`	수치 계산
`scikit-learn`	SVM 모델 실행 및 학습
`joblib`	`.pkl` 모델 및 스케일러 로드
---
6. 실행 방법
일반적인 사용 순서는 다음과 같습니다.
`python ui.py` 실행
브라우저에서 TwinGuard UI 접속
`보호 시작` 버튼 클릭
실시간 상태와 최근 탐지 결과 확인
종료할 때 `중지` 버튼 클릭
---
7. UI 주요 기능
TwinGuard UI는 다음 정보를 제공합니다.
보호 시작, 재시작, 중지 버튼
실시간 보호 상태
총 측정 수
정상 판단 수
위험 판단 수
최근 탐지 결과
탐지 세부 내용
RSSI 상태
RTT 상태
BSSID 변경 여부
AI 분석 결과
분석 단계 표시
패킷 수집
분석
결과 수신
다크모드 / 라이트모드 전환
---
8. 테스트 결과 및 현황
진행중
