# Fingerprint audit: http

- Date (UTC): 2026-11-11T09:16:28Z
- Tool revision: fd2d146 (from GIT_REVISION)
- Decoy: 127.0.0.1:48080 - engine fd2d146 in a throwaway container, identity seed 75, node controlled-test-node
- Reference: 127.0.0.1:42081 - nginx-focal: service: nginx;os: Ubuntu 20.04.6 LTS;apt_archive: snapshot.ubuntu.com 20231115T000000Z (focal, focal-updates, focal-security);package: nginx 1.18.0-0ubuntu1.4;package: nginx-core 1.18.0-0ubuntu1.4;package: nginx-common 1.18.0-0ubuntu1.4;config_sha256: /etc/nginx/nginx.conf 5e0b6c325d313dae7a3ec352503a39fa9319d1690946e89337fd7085727041c4;config_sha256: /etc/nginx/sites-enabled/default de6561b787412a46782cda0e20886d4e29ac5025a713c36535ffb28e58b7aa55;reports: nginx version: nginx/1.18.0 (Ubuntu);
- Network: both targets were reached at loopback addresses from the process that ran the audit, so both ran on the same machine
- Checks: 86, matching 82, differing 4
- Timing rows (informational): 1, outside tolerance 0


| Check | Comparison | Result | Similarity | Decoy | Reference |
|---|---|---|---|---|---|
| `http.get_root.status_line` | exact | match | 1.00 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |
| `http.get_root.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Last-Modified, Connecti...` | `Server, Date, Content-Type, Content-Length, Last-Modified, Connecti...` |
| `http.get_root.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.get_root.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.get_root.body` | bytes | match | 1.00 | `<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n...` | `<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n...` |
| `http.get_root.closes` | exact | match | 1.00 | `false` | `false` |
| `http.get_missing.status_line` | exact | match | 1.00 | `HTTP/1.1 404 Not Found` | `HTTP/1.1 404 Not Found` |
| `http.get_missing.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Connection` | `Server, Date, Content-Type, Content-Length, Connection` |
| `http.get_missing.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.get_missing.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.get_missing.body` | bytes | match | 1.00 | `<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<c...` | `<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<c...` |
| `http.get_missing.closes` | exact | match | 1.00 | `false` | `false` |
| `http.head_root.status_line` | exact | match | 1.00 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |
| `http.head_root.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Last-Modified, Connecti...` | `Server, Date, Content-Type, Content-Length, Last-Modified, Connecti...` |
| `http.head_root.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.head_root.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.head_root.body` | bytes | match | 1.00 | ` (0 bytes)` | ` (0 bytes)` |
| `http.head_root.closes` | exact | match | 1.00 | `false` | `false` |
| `http.options_root.status_line` | exact | match | 1.00 | `HTTP/1.1 405 Not Allowed` | `HTTP/1.1 405 Not Allowed` |
| `http.options_root.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Connection` | `Server, Date, Content-Type, Content-Length, Connection` |
| `http.options_root.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.options_root.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.options_root.body` | bytes | match | 1.00 | `<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n...` | `<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n...` |
| `http.options_root.closes` | exact | match | 1.00 | `false` | `false` |
| `http.post_root.status_line` | exact | match | 1.00 | `HTTP/1.1 405 Not Allowed` | `HTTP/1.1 405 Not Allowed` |
| `http.post_root.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Connection` | `Server, Date, Content-Type, Content-Length, Connection` |
| `http.post_root.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.post_root.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.post_root.body` | bytes | match | 1.00 | `<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n...` | `<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n...` |
| `http.post_root.closes` | exact | match | 1.00 | `false` | `false` |
| `http.delete_root.status_line` | exact | match | 1.00 | `HTTP/1.1 405 Not Allowed` | `HTTP/1.1 405 Not Allowed` |
| `http.delete_root.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Connection` | `Server, Date, Content-Type, Content-Length, Connection` |
| `http.delete_root.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.delete_root.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.delete_root.body` | bytes | match | 1.00 | `<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n...` | `<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n...` |
| `http.delete_root.closes` | exact | match | 1.00 | `false` | `false` |
| `http.unknown_method.status_line` | exact | match | 1.00 | `HTTP/1.1 405 Not Allowed` | `HTTP/1.1 405 Not Allowed` |
| `http.unknown_method.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Connection` | `Server, Date, Content-Type, Content-Length, Connection` |
| `http.unknown_method.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.unknown_method.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.unknown_method.body` | bytes | match | 1.00 | `<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n...` | `<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n...` |
| `http.unknown_method.closes` | exact | match | 1.00 | `false` | `false` |
| `http.malformed_request_line.status_line` | exact | match | 1.00 | `HTTP/1.1 400 Bad Request` | `HTTP/1.1 400 Bad Request` |
| `http.malformed_request_line.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Connection` | `Server, Date, Content-Type, Content-Length, Connection` |
| `http.malformed_request_line.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.malformed_request_line.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.malformed_request_line.body` | bytes | match | 1.00 | `<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n...` | `<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n...` |
| `http.malformed_request_line.closes` | exact | match | 1.00 | `true` | `true` |
| `http.http09_request.status_line` | exact | MISMATCH | 0.00 | `HTTP/1.1 200 OK` | `null` |
| `http.http09_request.header_names` | ordered | MISMATCH | 0.00 | `Server, Date, Content-Type, Content-Length, Last-Modified, Connecti...` | `(none)` |
| `http.http09_request.server` | exact | MISMATCH | 0.00 | `nginx/1.18.0 (Ubuntu)` | `null` |
| `http.http09_request.header_values` | exact | MISMATCH | 0.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{}` |
| `http.http09_request.body` | bytes | match | 1.00 | `<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n...` | `<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n...` |
| `http.http09_request.closes` | exact | match | 1.00 | `true` | `true` |
| `http.no_host_http11.status_line` | exact | match | 1.00 | `HTTP/1.1 400 Bad Request` | `HTTP/1.1 400 Bad Request` |
| `http.no_host_http11.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Connection` | `Server, Date, Content-Type, Content-Length, Connection` |
| `http.no_host_http11.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.no_host_http11.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.no_host_http11.body` | bytes | match | 1.00 | `<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n...` | `<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n...` |
| `http.no_host_http11.closes` | exact | match | 1.00 | `true` | `true` |
| `http.uri_9000.status_line` | exact | match | 1.00 | `HTTP/1.1 414 Request-URI Too Large` | `HTTP/1.1 414 Request-URI Too Large` |
| `http.uri_9000.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Connection` | `Server, Date, Content-Type, Content-Length, Connection` |
| `http.uri_9000.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.uri_9000.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.uri_9000.body` | bytes | match | 1.00 | `<html>\r\n<head><title>414 Request-URI Too Large</title></head>\r\n...` | `<html>\r\n<head><title>414 Request-URI Too Large</title></head>\r\n...` |
| `http.uri_9000.closes` | exact | match | 1.00 | `true` | `true` |
| `http.uri_70000.status_line` | exact | match | 1.00 | `HTTP/1.1 414 Request-URI Too Large` | `HTTP/1.1 414 Request-URI Too Large` |
| `http.uri_70000.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Connection` | `Server, Date, Content-Type, Content-Length, Connection` |
| `http.uri_70000.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.uri_70000.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.uri_70000.body` | bytes | match | 1.00 | `<html>\r\n<head><title>414 Request-URI Too Large</title></head>\r\n...` | `<html>\r\n<head><title>414 Request-URI Too Large</title></head>\r\n...` |
| `http.uri_70000.closes` | exact | match | 1.00 | `true` | `true` |
| `http.http10_no_headers.status_line` | exact | match | 1.00 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |
| `http.http10_no_headers.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Last-Modified, Connecti...` | `Server, Date, Content-Type, Content-Length, Last-Modified, Connecti...` |
| `http.http10_no_headers.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.http10_no_headers.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.http10_no_headers.body` | bytes | match | 1.00 | `<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n...` | `<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n...` |
| `http.http10_no_headers.closes` | exact | match | 1.00 | `true` | `true` |
| `http.connection_close.status_line` | exact | match | 1.00 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |
| `http.connection_close.header_names` | ordered | match | 1.00 | `Server, Date, Content-Type, Content-Length, Last-Modified, Connecti...` | `Server, Date, Content-Type, Content-Length, Last-Modified, Connecti...` |
| `http.connection_close.server` | exact | match | 1.00 | `nginx/1.18.0 (Ubuntu)` | `nginx/1.18.0 (Ubuntu)` |
| `http.connection_close.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` | `{"date": "<http-date>", "content-type": "text/html", "content-lengt...` |
| `http.connection_close.body` | bytes | match | 1.00 | `<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n...` | `<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n...` |
| `http.connection_close.closes` | exact | match | 1.00 | `true` | `true` |
| `http.keep_alive.second_request_answered` | exact | match | 1.00 | `true` | `true` |
| `http.keep_alive.connection_header` | exact | match | 1.00 | `keep-alive` | `keep-alive` |
| `http.response_latency` | timing | within tolerance | 0.00 | `0.006` | `0.0` |
