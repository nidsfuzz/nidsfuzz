HTTP_STICKY_BUFFER = [
    "http_uri", "http_raw_uri",
    "http_header", "http_raw_header",
    "http_cookie", "http_raw_cookie",
    "http_client_body", "http_raw_body",
    "http_param",
    "http_method",
    "http_version",
    "http_stat_code",
    "http_stat_msg",
    "http_raw_request", "http_raw_status",
    "http_trailer", "http_raw_trailer",
    "http_true_ip",
]

GENERAL_STICKY_BUFFER = [
    "pkt_data",
    "raw_data",
    "file_data",
    "js_data",
    "vba_data",
    "base64_data"
]

STICKY_BUFFER = HTTP_STICKY_BUFFER + GENERAL_STICKY_BUFFER
