#!/usr/bin/env python
# coding: utf-8

from token import *


def test_gen_token():
    app_id = 12345
    app_secret = bytearray(b'appkey1234')

    tk = Token(app_id, app_secret)

    uid = "987654321"
    valid_time = 600000
    build_timestamp_mills = 1563526401661
    parameter = {"你": "好", "442cd": "fdsaf545", "fdy": "soie4"}
    privileges = {"你": 123412133540, "442cd": 12345453540, "fdy": 1234503540}

    token = tk.gen(uid, parameter, privileges, build_timestamp_mills, valid_time)
    print "Gen:\n\t", token


def test_parse_token():
    app_id = 12345
    app_secret = bytearray(b'appkey1234')

    tk = Token(app_id, app_secret)

    token = "_2dllwAAAG8AADA5AAUxMzIxMgACAAVwa2V5MQAFcHZhbDEABXBrZXkyAAVwdmFsMgACAARwcmkxAAAAAAAAAAEABHByaTIAAAAAAAAAAgAAAWwn1q9vAAAALmE2hvjGAlnQ85ey5GVjrd_120qE"
    yctk, err = tk.parse(token)
    if err != None:
        print "Parse:\n\t", err
    else:
        print "Parse:\n\tsucc\n\t", str(yctk)


if __name__ == '__main__':

    test_gen_token()

    test_parse_token()
