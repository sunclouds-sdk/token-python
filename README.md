# token-python
本文介绍了python版YCToken SDK的使用方法，并提供了产YCToken和验YCToken的代码示例（最新版本v1.0.0）。

# 描述
YCToken能够支持身份验证和过期时间验证，并支持业务参数的透传（不对业务参数进行校验）。

# 示例代码
**产token** 
    
    app_id = 12345
    app_secret = bytearray(b'appkey1234')
    uid = "987654321"
    valid_time = 600000
    build_timestamp = 1563526401661
    // 设置业务参数
    parameter = {"pkey1": "pval1", "pkey2": "pval2"}
    // 设置业务权限
    privileges = {"pri1": 300, "pri2": 400}
    // 生成token 串
    token_str = YCToken().gen(app_id, app_secret, uid, parameter, privileges, build_timestamp, valid_time) 
 
 
 **验token** 
    
    // 解析token串，生成YCToken对象
    app_secret = bytearray(b'appkey1234')
    token_str = "_2dllwAAAG8AADA5AAUxMzIxMgACAAVwa2V5MQAFcHZhbDEABXBrZXkyAAVwdmFsMgACAARwcmkxAAAAAAAAAAEABHByaTIAAAAAAAAAAgAAAWwn1q9vAAAALmE2hvjGAlnQ85ey5GVjrd_120qE"

    yt, err = YCToken().parse(token_str, app_secret)
    
    if err != None:
        // print err
    else:
        // check valid time
        // do something

 
 
# 其他语言的YCToken SDK
 
其他语言的YCToken SDK源码及它们的介绍、示例代码地址如下：

**java**

https://github.com/sunclouds-sdk/token-java
 
**golang**

https://github.com/sunclouds-sdk/token-golang
 
