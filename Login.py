'''
Descripttion: 
version: 
Author: WZQ
Date: 2021-08-20 15:53:10
LastEditors: WZQ
LastEditTime: 2021-08-20 17:36:09
'''

import os
import requests
import time
import re

from encryption.srun_md5 import *
from encryption.srun_sha1 import *
from encryption.srun_base64 import *
from encryption.srun_xencode import *

header={
	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'
}

class LoginManager:
    def __init__(self):
        self.url_login_page = "http://124.16.81.61/srun_portal_pc?ac_id=1&theme=pro"
        self.url_get_challenge_api  = "http://124.16.81.61/cgi-bin/get_challenge"
        self.url_login_api = "http://124.16.81.61/cgi-bin/srun_portal"
   
        self.n = "200"
        self.type = "1"
        self.ac_id = "1"

    def login(self, username, password):
        self.username = username
        self.password = password

        self.get_ip()
        self.get_token()
        self.get_login_response()

    # * Step 1
    def get_ip(self):
        self._get_login_page()
        self._resolve_ip_from_login_page()
        print("----------------")  

    def _get_login_page(self):
        self._page_response = requests.get(self.url_login_page, headers=header)

    def _resolve_ip_from_login_page(self):
        self.ip = re.search('ip     : "(.*?)",', self._page_response.text).group(1)
        print("Current IP :", self.ip)

    # * Step 2
    def get_token(self):
        self._get_challenge()
        self._resolve_token_from_challenge_response()
        print("----------------")

    def _get_challenge(self):
        """
        The 'get_challenge' request aims to ask the server to generate a token
        """
        params_get_challenge = {
            "callback": "jsonp1583251661367", # This value can be any string, but cannot be absent
            "username": self.username,
            "ip": self.ip
        }
        self._challenge_response = requests.get(self.url_get_challenge_api, params=params_get_challenge, headers=header)

        if "200" in str(self._challenge_response):
            print("Get tokens Success!")
        else:
            print("Get tokens Fail!")

    def _resolve_token_from_challenge_response(self):
        self.token = re.search('"challenge":"(.*?)"', self._challenge_response.text).group(1)
	
    # * Step 3
    def get_login_response(self):
        self._generate_encrypted_login_info()
        self._send_login_info()
        self._resolve_login_response()
        print("The login result : " + self._login_result)
        print("----------------")
    
    # encryp algorithm for message passing and login
    def _generate_encrypted_login_info(self):
        self._generate_info()
        self._encrypt_info()
        self._generate_md5()
        self._encrypt_md5()
        self._generate_chksum()
        self._encrypt_chksum()

    def _send_login_info(self):
        login_info_params = {
            'callback': 'jsonp1583251661368', # This value can be any string, but cannot be absent
            'action':'login',
            'username': self.username,
            'password': self.encrypted_md5,
            'ac_id': self.ac_id,
            'ip': self.ip,
            'info': self.encrypted_info,
            'chksum': self.encrypted_chkstr,
            'n': self.n,
            'type': self.type
        }
        self._login_response = requests.get(self.url_login_api, params=login_info_params, headers=header)

    def _resolve_login_response(self):
        self._login_result = re.search('"suc_msg":"(.*?)"', self._login_response.text).group(1)

    def _generate_info(self):
        info_params = {
            "username": self.username,
            "password": self.password,
            "ip": self.ip,
            "ac_id": self.ac_id,
        }
        info = re.sub("'",'"',str(info_params))
        self.info = re.sub(" ",'',info)

    def _encrypt_info(self):
        self.encrypted_info = "{SRBX1}" + get_base64(get_xencode(self.info, self.token))

    def _generate_md5(self):
        self.md5 = get_md5("", self.token)
    
    def _encrypt_md5(self):
        self.encrypted_md5 = "{MD5}" + self.md5

    def _generate_chksum(self):
        self.chkstr = self.token + self.username
        self.chkstr += self.token + self.md5
        self.chkstr += self.token + self.ac_id
        self.chkstr += self.token + self.ip
        self.chkstr += self.token + self.n
        self.chkstr += self.token + self.type
        self.chkstr += self.token + self.encrypted_info 

    def _encrypt_chksum(self):
        self.encrypted_chkstr = get_sha1(self.chkstr)


def connectionTest():
    status = os.system("ping www.baidu.com -c 8")
    return status == 0

def loadAccount():
    lines = []
    account = ("username", "password")
    with open('./account.txt') as f:
        for line in  f.readlines():
            lines.append(line.strip())
    return lines

if __name__ == '__main__':
    print("=================================================")
    print(">>            UCAS Network Login for           <<")
    print(">>      SRunCGIAuthIntfSvr V1.18 B20210412     <<")
    print("=================================================")

    account = loadAccount()
    username = account[0]
    password = account[1]
    LM = LoginManager()
    
    print(">>>>>>>>Begin First Login<<<<<<<<")
    LM.login(username, password)

    # circle login
    checkinterval = 6*60
    timestamp = lambda : print(time.asctime(time.localtime(time.time())))
    
    print(">>>>>>>Begin Auto Connection<<<<<<<")
    while 1:
        time.sleep(checkinterval)
        if not connectionTest():
            timestamp()
            LM.login(username, password)
