#!/usr/bin/env python
# coding: utf-8

from yctoken import *


def gen_token():
    app_id = 12345
    app_secret = bytearray(b'appkey1234')
    uid = "987654321"
    valid_time = 60000
    build_timestamp = int(time.time() * 1000)
    parameter = {"pkey1": "pval1", "pkey2": "pval2"}
    privileges = {"pri1": 300, "pri2": 400}

    token_str = YCToken().gen(app_id, app_secret, uid, parameter, privileges, build_timestamp, valid_time)
    print "Gen: ", token_str, "\n"


def parse_token():
    app_secret = bytearray(b'appkey1234')
    token_str = "_2dllwAAAHMAADA5AAk5ODc2NTQzMjEAAgAFcGtleTIABXB2YWwyAAVwa2V5MQAFcHZhbDEAAgAEcHJpMQAAAAAAAAEsAARwcmkyAAAAAAAAAZAAAAFsuAVsTAAA6mDjTWxNCdjou_5GyCFCWLtGAgn9Ww"

    yt, err = YCToken().parse(token_str, app_secret)
    if err != None:
        print "Parse: Fail. ", err
    else:
        print "Parse: Succ."
        if yt.validate():
            print "Validate: Succ."
        else:
            print "Validate: Fail."

        print str(yt), "\n"


if __name__ == '__main__':
    gen_token()

    parse_token()
