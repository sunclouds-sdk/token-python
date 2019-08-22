#!/usr/bin/env python
# coding: utf-8

import hashlib, hmac
import base64
import struct
import time
import binascii

BASELEN = 50
MACLEN = 20


class YCToken:
    def __init__(self):
        self.token_version = -10001001          # token版本字段
        self.token_len = 0                      # 整个token的字节长度
        self.app_id = 0                         # 项目ID
        self.uid = ""                           # 在项目内唯一的用户ID
        self.parameter = dict()                 # 权限的参数
        self.privileges = dict()                # 各项权限对应的过期时间，UTC时间，单位毫秒
        self.build_timestamp = 0          # token的创建时间（UTC时间，单位毫秒）
        self.valid_time = 0                     # token有效时长（单位秒）
        self.digital_signature = bytearray(20)  # 数字签名:hmac-sha1算法对digital_signature前的所有数据运算得出，密钥使用appSecret

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)


    def gen(this, app_id, app_secret, uid, parameter, privileges, build_timestamp, valid_time):
        """生成token.
    
           Args:
               app_id: 项目ID, int32
               app_secret: 项目ID对应的密钥
               uid: 在项目内唯一的用户ID, string
               token_version: token版本, int32
               parameter: 权限的参数, map[string][string]
               privileges: 各项权限对应的过期时间，UTC时间，单位毫秒, map[string][int64]
               build_timestamp: token的创建时间(UTC时间，单位毫秒), int64
               valid_time: token有效时长(单位秒), int32
    
           Returns:
               整个token经过url安全的base64编码后的字符串
           """
    
        uid_bytes = struct.pack('>h%ds' % (len(uid)), len(uid), uid)
    
        parameter_bytes = ''
        for (k, v) in parameter.items():
            parameter_bytes = parameter_bytes + struct.pack('>h%dsh%ds' % (len(k), len(v)), len(k), k, len(v), v)
    
        privileges_bytes = ''
        for (k, v) in privileges.items():
            privileges_bytes = privileges_bytes + struct.pack('>h%dsq' % (len(k)), len(k), k, v)
    
        token_len = BASELEN + len(uid) + len(parameter_bytes) + len(privileges_bytes)
    
        barray = struct.pack('>lll', this.token_version, token_len, app_id) + uid_bytes \
                 + struct.pack('>h', len(parameter)) + parameter_bytes \
                 + struct.pack('>h', len(privileges)) + privileges_bytes \
                 + struct.pack('>ql', build_timestamp, valid_time)
    
        mac = hmac.new(app_secret, barray, hashlib.sha1)
        barray = barray + mac.digest()
    
        # print len(barray), type(barray), binascii.hexlify(barray)
        # 通过url传输时去掉=号
        return base64.urlsafe_b64encode(str(barray)).rstrip('=')
    
    
    def parse(this, b64token, app_secret):
        """解析token.
    
           Args:
               b64token: 整个token经过url安全的base64编码后的字符串, string
               app_secret: 项目ID对应的密钥
    
           Returns:
               YCToken:解析出来的token内容
           """
        tk = YCToken()
    
        err = None
        try:
            # 通过url传输时去掉了=号，所以需要补上=号
            des = base64.urlsafe_b64decode(str(b64token + '=' * (4 - len(b64token) % 4)))
            # print len(des), type(des), binascii.hexlify(des)
    
            pos = 0
            tk.token_version, tk.token_len, tk.app_id, uid_len, = struct.unpack('>lllh', des[pos:pos + 14])
            pos += 14
    
            tk.uid, = struct.unpack('>%ds' % (uid_len), des[pos:pos + uid_len])
            pos += uid_len
    
            parameter_len, = struct.unpack('>h', des[pos:pos + 2])
            pos += 2
    
            for i in range(0, parameter_len):
                key_len, = struct.unpack('>h', des[pos:pos + 2])
                key, = struct.unpack('>%ds' % (key_len), des[pos + 2:pos + 2 + key_len])
                value_len, = struct.unpack('>h', des[pos + 2 + key_len:pos + 2 + key_len + 2])
                value, = struct.unpack('>%ds' % (value_len), des[pos + 2 + key_len + 2:pos + 2 + key_len + 2 + value_len])
    
                tk.parameter[key] = value
                pos += 2 + key_len + 2 + value_len
    
            privileges_len, = struct.unpack('>h', des[pos:pos + 2])
            pos += 2
    
            for i in range(0, privileges_len):
                key_len, = struct.unpack('>h', des[pos:pos + 2])
                key, = struct.unpack('>%ds' % (key_len), des[pos + 2:pos + 2 + key_len])
                value, = struct.unpack('>q', des[pos + 2 + key_len:pos + 2 + key_len + 8])
    
                tk.privileges[key] = value
                pos += 2 + key_len + 8
    
            tk.build_timestamp, tk.valid_time, = struct.unpack('>ql', des[pos:pos + 12])
            pos += 12
    
            tk.digital_signature = des[pos:tk.token_len]
    
            barray = des[0:len(des) - MACLEN]
            mac = hmac.new(app_secret, barray, hashlib.sha1)
            sign = mac.digest()
    
            if sign != tk.digital_signature:
                err = "sign error"
        except Exception as e:
            err = "parse token err:" + str(e)
    
        return tk, err


    def validate(this):
        if this.build_timestamp + this.valid_time * 1000 > int(time.time() * 1000):
            return True
        return False