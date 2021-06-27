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