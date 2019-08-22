#!/usr/bin/env python
# coding: utf-8

from yctoken import *


def gen_token():
    app_id = 12345
    app_secret = bytearray(b'appkey1234')
    uid = "987654321"
    valid_time = 600000
    build_timestamp = 1563526401661
    parameter = {"你": "好", "442cd": "fdsaf545", "fdy": "soie4"}
    privileges = {"你": 123412133540, "442cd": 12345453540, "fdy": 1234503540}

    token_str = YCToken().gen(app_id, app_secret, uid, parameter, privileges, build_timestamp, valid_time)
    print "Gen:\n\t", token_str


def parse_token():
    app_secret = bytearray(b'appkey1234')
    token_str = "_2dllwAAAG8AADA5AAUxMzIxMgACAAVwa2V5MQAFcHZhbDEABXBrZXkyAAVwdmFsMgACAARwcmkxAAAAAAAAAAEABHByaTIAAAAAAAAAAgAAAWwn1q9vAAAALmE2hvjGAlnQ85ey5GVjrd_120qE"

    yt, err = YCToken().parse(token_str, app_secret)
    if err != None:
        print "Parse:\n\t", err
    else:
        print "Parse:\n\tsucc\n\t", str(yt)


if __name__ == '__main__':

    gen_token()

    parse_token()
