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