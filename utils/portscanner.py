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
