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