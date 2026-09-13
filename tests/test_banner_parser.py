from nsm.services.banner_parser import BannerParser


def test_parse_openssh_banner():
    banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"

    result = BannerParser.parse(banner)

    assert result is not None
    assert result.product == "OpenSSH"
    assert result.version == "9.6p1"


def test_parse_openssh_without_patch_level():
    banner = "SSH-2.0-OpenSSH_9.6"

    result = BannerParser.parse(banner)

    assert result is not None
    assert result.product == "OpenSSH"
    assert result.version == "9.6"


def test_parse_empty_banner():
    result = BannerParser.parse("")

    assert result is None


def test_parse_unknown_banner():
    banner = "SomeRandomService 1.2.3"

    result = BannerParser.parse(banner)

    assert result is None

def test_parse_nginx_banner():
    banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"

    result = BannerParser.parse(banner)

    assert result is not None
    assert result.product == "nginx"
    assert result.version == "1.24.0"

def test_parse_vsftpd_banner():
    banner = "220 (vsFTPd 3.0.5)"

    result = BannerParser.parse(banner)

    assert result is not None
    assert result.product == "vsFTPd"
    assert result.version == "3.0.5"

def test_parse_apache_banner():
    banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\n"

    result = BannerParser.parse(banner)

    assert result is not None
    assert result.product == "Apache"
    assert result.version == "2.4.58"

def test_parse_nginx_banner_with_extra_information():
    banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\n"

    result = BannerParser.parse(banner)

    assert result is not None
    assert result.product == "nginx"
    assert result.version == "1.24.0"

def test_parse_server_without_version():
    banner = "HTTP/1.1 200 OK\r\nServer: nginx\r\n"

    result = BannerParser.parse(banner)

    assert result is not None
    assert result.product == "nginx"
    assert result.version is None

def test_parse_malformed_server_banner():
    banner = "HTTP/1.1 200 OK\r\nServer: /\r\n"

    result = BannerParser.parse(banner)

    assert result is None