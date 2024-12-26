# -- coding: utf-8 -- 
# Name: http_responses.py
# Where:
def http_response_200():
    """
    生成HTTP 200 OK响应。
    """
    # body = "<html><body><h1>OK</h1></body></html>"
    body = ("root@localhost c4ca4238a0b923820dcc509a6f75849b\x0d\x0a"
            "<img src=1 onerror=alert(1)> <img src=1 onerror=prompt(1)> <script>alert(1)</script>\x0d\x0a"
            "DB_NAME DB_PASSWD\x0d\x0a"
            "<title>phpinfo()</title> PHP Version")
    headers = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=UTF-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "\r\n"
    ]
    return "\r\n".join(headers) + body


def http_response_302(location='http://example.com'):
    """
    生成HTTP 302 Found响应，用于重定向。
    """
    body = f"<html><body><h1>302 Found</h1><p>Redirecting to <a href='{location}'>{location}</a></p></body></html>"
    headers = [
        "HTTP/1.1 302 Found",
        f"Location: {location}",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "\r\n"
    ]
    return "\r\n".join(headers) + body


def http_response_404():
    """
    生成HTTP 404 Not Found响应。
    """
    body = "<html><body><h1>Not Found</h1></body></html>"
    headers = [
        "HTTP/1.1 404 Not Found",
        "Content-Type: text/html; charset=UTF-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "\r\n"
    ]
    return "\r\n".join(headers) + body


def http_response_502():
    """
    生成HTTP 502 Bad Gateway响应。
    """
    body = "<html><body><h1>Bad Gateway</h1></body></html>"
    headers = [
        "HTTP/1.1 502 Bad Gateway",
        "Content-Type: text/html; charset=UTF-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "\r\n"
    ]
    return "\r\n".join(headers) + body
