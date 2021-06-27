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