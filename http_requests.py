# -- coding: utf-8 -- 
# Name: http_requests.py
# Where:
# http_requests.py
def standard_get():
    """
    生成标准的HTTP GET请求。
    """
    return "GET /path?query=param HTTP/1.1\r\nHost: example.com\r\n\r\n"


def ordinary_post():
    """
    生成普通的HTTP POST请求，使用application/x-www-form-urlencoded内容类型。
    """
    return ("POST /path HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 27\r\n"
            "\r\n"
            "field1=value1&field2=value2")


def form_submission():
    """
    生成带有表单数据的HTTP POST请求，使用multipart/form-data内容类型。
    """
    return ("POST /path HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
            "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
            "Content-Disposition: form-data; name=\"field1\"\r\n"
            "\r\n"
            "value1\r\n"
            "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
            "Content-Disposition: form-data; name=\"field2\"; filename=\"1.php\"\r\n"
            "\r\n"
            "<?php phpinfo();?>\r\n"
            "------WebKitFormBoundary7MA4YWxkTrZu0gW--")