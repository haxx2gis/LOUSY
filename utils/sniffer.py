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