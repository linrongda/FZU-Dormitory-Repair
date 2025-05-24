# -*- coding:utf-8 -*-

import binascii

import re
import requests
from Crypto.Cipher import AES


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    对数据进行 PKCS#7 填充
    :param data: 待填充的原始字节串
    :param block_size: 块大小，AES 固定为 16
    :return: 填充后的字节串
    """
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def aes_encrypt_raw(s: str, key_bytes: bytes) -> bytes:
    """
    AES-ECB 加密（底层函数）
    :param s: 原始字符串
    :param key_bytes: 16/24/32 字节的 AES 密钥
    :return: 加密后 bytes
    """
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    padded = pkcs7_pad(s.encode('utf-8'))
    return cipher.encrypt(padded)


def encrypt(pd: str, key_b64: str) -> str:
    """
    密码加密过程（AES-ECB + PKCS#7 + Base64）：
    1. 从认证页面获取 base64 格式的密钥
    2. 将密钥解码成 bytes 格式
    3. 对明文密码进行 AES-ECB 加密（PKCS#7 填充）
    4. 将加密结果 Base64 编码后返回
    :param pd: 明文密码
    :param key_b64: Base64 编码的密钥字符串
    :return: 加密后的密码（Base64 格式字符串）
    """
    key_bytes = binascii.a2b_base64(key_b64.encode('utf-8'))  # 解码 Base64 得到密钥 bytes
    encrypted_bytes = aes_encrypt_raw(pd, key_bytes)  # 得到加密后的 bytes
    return binascii.b2a_base64(encrypted_bytes, newline=False).decode('utf-8')


def login(username, password):
    # 访问登录界面，返回认证页面的内容，同时获得一个cookie：SESSION（禁止重定向）
    url = 'https://sso.fzu.edu.cn/login'
    resp = requests.get(url, allow_redirects=False)

    # 从认证页面正则得到 croypto（** base64格式） 与 execution（post参数）的值
    croypto = re.search(r'"login-croypto">(.*?)<', resp.text, re.S).group(1)
    # print(croypto)
    execution = re.search(r'"login-page-flowkey">(.*?)<', resp.text, re.S).group(1)
    # print(execution)
    # 构建post数据 填入自己的学号 密码
    data = {
        'username': username,  # 学号
        'type': 'UsernamePassword',
        '_eventId': 'submit',
        'geolocation': '',
        'execution': execution,
        'captcha_code': '',
        'croypto': croypto,  # ** base64格式
        'password': encrypt(password, croypto),  # 密码 经过aes加密 base64格式
        'captcha_payload': encrypt('{}', croypto)  # 验证码 经过aes加密 base64格式
    }

    # 提交数据，进行登录，注意携带cookie（禁重定向）
    url = 'https://sso.fzu.edu.cn/login'
    cookies = {'SESSION': resp.cookies.get_dict()['SESSION']}
    resp = requests.post(url, data=data, allow_redirects=False, cookies=cookies)
    if resp.status_code == 302:
        print('成功登录')

    # 通过统一认证访问“宿舍报修”页面，这个页面需要cookie，所以要带上前面登录获得的cookie：SOURCEID_TGC（禁止重定向）
    url = 'https://sso.fzu.edu.cn/login?service=http:%2F%2Fehall.fzu.edu.cn%2Fssfw%2Fsys%2Fswmssbxapp%2F*default%2Findex.do'
    cookies = {'SOURCEID_TGC': resp.cookies.get_dict()['SOURCEID_TGC']}
    resp = requests.get(url, allow_redirects=False, cookies=cookies)
    # 返回重定向后的url，这个url就是“宿舍报修”页面的url
    url = resp.headers['Location']
    resp = requests.get(url, allow_redirects=False)
    # 访问该url不需要携带cookie，通过url路径中的ticket作为凭证

    # 访问后会有返回一个_WEU的cookie（办事大厅所用到的cookie），后续页面请求的js等需要这个cookie
    cookies = {'_WEU': resp.cookies.get_dict()['_WEU']}

    # 第一次更新cookie
    url = 'http://ehall.fzu.edu.cn/ssfw/sys/emappagelog/config/swmssbxapp.do'
    resp = requests.get(url, allow_redirects=False, cookies=cookies)

    # 第二次更新cookie
    url = 'http://ehall.fzu.edu.cn/ssfw/sys/xgutilapp/MobileCommon/getSelRoleConfig.do'
    data = {'data': '{"APPID":"4970001248812463","APPNAME":"swmssbxapp"}'}
    cookies['_WEU'] = resp.cookies.get_dict()['_WEU']
    resp = requests.post(url, allow_redirects=False, cookies=cookies, data=data)

    # 第三次更新cookie
    url = 'http://ehall.fzu.edu.cn/ssfw/sys/xgutilapp/MobileCommon/getMenuInfo.do'
    cookies['_WEU'] = resp.cookies.get_dict()['_WEU']
    resp = requests.post(url, allow_redirects=False, cookies=cookies, data=data)

    # 获取报修记录
    url = 'http://ehall.fzu.edu.cn/ssfw/sys/swmssbxapp/MyRepairController/getUsrRepairRecords.do'
    cookies['_WEU'] = resp.cookies.get_dict()['_WEU']
    data = {'data': '{"querySetting":"[]"}'}
    resp = requests.post(url, allow_redirects=False, cookies=cookies, data=data)

    print(cookies)
    print(resp.text)
    print(resp.headers)


if __name__ == '__main__':
    username = ''  # 学号
    password = ''  # 密码
    login(username, password)
