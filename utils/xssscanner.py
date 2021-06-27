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