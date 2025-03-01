# -*- coding:utf-8 -*-

import binascii

import re
import requests
from pyDes import des, PAD_PKCS5, ECB


def des_encrypt(s, key):
    """
    DES 加密
    :param key: 秘钥
    :param s: 原始字符串
    :return: 加密后字符串，16进制
    """
    secret_key = key
    k = des(secret_key, mode=ECB, pad=None, padmode=PAD_PKCS5)
    en = k.encrypt(s, padmode=PAD_PKCS5)
    return en  # 得到加密后的16位进制密码 <class 'bytes'>


def encrypt(pd, key):
    """
    密码加密过程：
    1 从认证页面中可获得base64格式的秘钥
    2 将秘钥解码成bytes格式
    3 输入明文密码
    4 通过des加密明文密码
    5 返回base64编码格式的加密后密码
    :param pd: 明文密码
    :param key: 秘钥
    :return: 加密后的密码（base64格式）
    """
    key = binascii.a2b_base64(key.encode('utf-8'))  # 先解码 <class 'bytes'>
    pd_bytes = des_encrypt(pd, key)  # 得到加密后的16位进制密码 <class 'bytes'>
    pd_base64 = binascii.b2a_base64(pd_bytes, newline=False).decode('utf-8')
    # print(pd_base64)
    return pd_base64


def login(username, password):
    headers = {
        'Connection': 'keep-alive',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.9',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/95.0.4638.69 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # 访问登录界面，返回认证页面的内容，同时获得一个cookie：SESSION（禁止重定向）
    url = 'https://sso.fzu.edu.cn/login'
    resp = requests.get(url, allow_redirects=False, headers=headers)

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
        'password': encrypt(password, croypto)  # 密码 经过des加密 base64格式
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
    # 访问该url不需要携带cookie，可能服务端通过ip或其他信息记录
    # 访问后会有返回JSESSIONID和_WEU，两种cookie（办事大厅所用到的cookie），后续页面请求的js等需要这两种cookie
    print(resp.text)
    print(resp.headers)


if __name__ == '__main__':
    username = ''  # 学号
    password = ''  # 密码
    login(username, password)
