import subprocess
import sys
import socket
import time
import os
import signal

# --- 설정 ---
# Windows에서는 '127.0.0.1'을 사용
IP = "127.0.0.1"
PORT = 5003  # Detector(Code4)로부터 결과를 받을 포트

# 실행할 파일 이름들 (본인 파일명으로 수정 필수!)
# 예: CAPTURE_SCRIPT = "code1.py"
CAPTURE_SCRIPT = "PacketCapture.py"     # 1번 코드
EXTRACT_SCRIPT = "Preprocessor.py"           # 2번 코드
DETECTOR_SCRIPT = "AnomalyDetector.py"  # 4번 코드

# --- 결과 수신 함수 ---
def socket_listen(sock):
    """ 5003번 포트로 들어오는 탐지 결과를 받아서 출력 """
    print(f"🎧 [UI] 탐지 결과 모니터링 중 ({IP}:{PORT})... (Ctrl+C로 종료)")
    try:
        while True:
            # 윈도우에서는 버퍼 크기를 넉넉하게 잡는 게 좋습니다.
            data, addr = sock.recvfrom(4096)
            
            # 들어온 데이터(결과) 출력
            print(f"\n🔔 [ALERT] 탐지 결과:\n{data.decode('utf-8')}")
            print("-" * 30)
            
    except KeyboardInterrupt:
        print("\n🛑 모니터링 종료.")
    except Exception as e:
        print(f"❌ 소켓 오류: {e}")

# --- 메인 실행 함수 ---
def main():
    print(f"=== TwinGuard Windows UI Started on {sys.platform} ===")

    # 로그 파일 생성
    capturer_log = open("capturer.log", "w")
    preprocessor_log = open("preprocessor.log", "w")
    detector_log = open("detector.log", "w")

    print("🚀 하위 프로세스(Capture, Preprocessor, Detector) 실행 중...")

    proc_capture = None
    proc_extract = None
    proc_detector = None

    try:
        # 1. 윈도우용 subprocess 실행 (python 명령어 사용)
        
        # Detector (결과 수신자, Port 5002) - 가장 먼저 실행
        proc_detector = subprocess.Popen(
            ["python", "-u", DETECTOR_SCRIPT], 
            stdout=detector_log, 
            stderr=detector_log
        )

        # Preprocessor (중계자, Port 5001 -> 5002)
        proc_extract = subprocess.Popen(
            ["python", "-u", EXTRACT_SCRIPT], 
            stdout=preprocessor_log, 
            stderr=preprocessor_log
        )
        
        # Capture (데이터 발신자, Port 5001) - 가장 나중에 실행
        proc_capture = subprocess.Popen(
            ["python", "-u", CAPTURE_SCRIPT], 
            stdout=capturer_log, 
            stderr=capturer_log
        )
        
        print("✅ 모든 프로세스 실행 완료.")

    except FileNotFoundError as e:
        print(f"❌ 파일 실행 실패! 파일명이 맞는지 확인하세요: {e}")
        return

    # 2. 결과 수신용 소켓 생성 (UI <- Detector)
    try:
        input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        input_sock.bind((IP, PORT))
    except Exception as e:
        print(f"❌ UI 소켓 생성 실패 (포트 5003 충돌?): {e}")
        return

    # 3. 사용자 메뉴
    try:
        while True:
            print("\n[MENU]")
            print("1. 실시간 탐지 결과 보기 (모니터링 시작)")
            print("0. 프로그램 종료")
            
            choice = input("선택 >> ")
            
            if choice == "0":
                print("프로그램을 종료합니다...")
                break
            elif choice == "1":
                socket_listen(input_sock)
            else:
                print("잘못된 입력입니다.")
                
    except KeyboardInterrupt:
        print("\n강제 종료됨.")
        
    finally:
        # --- 종료 시 자식 프로세스 정리 (필수) ---
        print("💀 하위 프로세스 강제 종료 중...")
        if proc_capture: proc_capture.terminate()
        if proc_extract: proc_extract.terminate()
        if proc_detector: proc_detector.terminate()
        
        capturer_log.close()
        preprocessor_log.close()
        detector_log.close()
        input_sock.close()
        print("✅ 종료 완료.")

if __name__ == "__main__":
    main()