# Fingerprint audit: http

- Date (UTC): 2026-11-11T09:15:15Z
- Tool revision: fd2d146 (from GIT_REVISION)
- Decoy: 127.0.0.1:48080 - engine fd2d146 in a throwaway container, identity seed 8, node controlled-test-node
- Reference: 127.0.0.1:42080 - apache-focal: service: apache;os: Ubuntu 20.04.6 LTS;apt_archive: snapshot.ubuntu.com 20231115T000000Z (focal, focal-updates, focal-security);package: apache2 2.4.41-4ubuntu3.14;package: apache2-bin 2.4.41-4ubuntu3.14;package: libapache2-mod-php7.4 7.4.3-4ubuntu2.19;config_sha256: /etc/apache2/apache2.conf 312efde2815c23e529bdef9d8ab05f4729636962a7077a789377db56c56ab7e8;config_sha256: /etc/apache2/sites-enabled/000-default.conf fdd55ad7cf9b495bccdd8465f37bbfe1577068b24abae0f3d934b6a1d1d29331;config_sha256: /etc/apache2/conf-enabled/security.conf fc9c6ed5df6813f95b910e9040d79b40aec98617e57fe9f2b5ae21055b77e1
- Network: both targets were reached at loopback addresses from the process that ran the audit, so both ran on the same machine
- Checks: 86, matching 58, differing 28
- Timing rows (informational): 1, outside tolerance 0


| Check | Comparison | Result | Similarity | Decoy | Reference |
|---|---|---|---|---|---|
| `http.get_root.status_line` | exact | match | 1.00 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |
| `http.get_root.header_names` | ordered | match | 1.00 | `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, V...` | `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, V...` |
| `http.get_root.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.get_root.header_values` | exact | MISMATCH | 0.86 | `{"date": "<http-date>", "last-modified": "<http-date>", "etag": "<e...` | `{"date": "<http-date>", "last-modified": "<http-date>", "etag": "<e...` |
| `http.get_root.body` | bytes | MISMATCH | 0.91 | `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "htt...` | `\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "h...` |
| `http.get_root.closes` | exact | match | 1.00 | `false` | `false` |
| `http.get_missing.status_line` | exact | match | 1.00 | `HTTP/1.1 404 Not Found` | `HTTP/1.1 404 Not Found` |
| `http.get_missing.header_names` | ordered | match | 1.00 | `Date, Server, Content-Length, Content-Type` | `Date, Server, Content-Length, Content-Type` |
| `http.get_missing.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.get_missing.header_values` | exact | match | 1.00 | `{"date": "<http-date>", "content-length": "271", "content-type": "t...` | `{"date": "<http-date>", "content-length": "271", "content-type": "t...` |
| `http.get_missing.body` | bytes | match | 1.00 | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` |
| `http.get_missing.closes` | exact | match | 1.00 | `false` | `false` |
| `http.head_root.status_line` | exact | match | 1.00 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |
| `http.head_root.header_names` | ordered | match | 1.00 | `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, V...` | `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, V...` |
| `http.head_root.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.head_root.header_values` | exact | MISMATCH | 0.86 | `{"date": "<http-date>", "last-modified": "<http-date>", "etag": "<e...` | `{"date": "<http-date>", "last-modified": "<http-date>", "etag": "<e...` |
| `http.head_root.body` | bytes | match | 1.00 | ` (0 bytes)` | ` (0 bytes)` |
| `http.head_root.closes` | exact | match | 1.00 | `false` | `false` |
| `http.options_root.status_line` | exact | match | 1.00 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |
| `http.options_root.header_names` | ordered | match | 1.00 | `Date, Server, Allow, Content-Length, Content-Type` | `Date, Server, Allow, Content-Length, Content-Type` |
| `http.options_root.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.options_root.header_values` | exact | MISMATCH | 0.75 | `{"date": "<http-date>", "allow": "POST,OPTIONS,HEAD,GET", "content-...` | `{"date": "<http-date>", "allow": "GET,POST,OPTIONS,HEAD", "content-...` |
| `http.options_root.body` | bytes | match | 1.00 | ` (0 bytes)` | ` (0 bytes)` |
| `http.options_root.closes` | exact | match | 1.00 | `false` | `false` |
| `http.post_root.status_line` | exact | MISMATCH | 0.59 | `HTTP/1.1 405 Method Not Allowed` | `HTTP/1.1 200 OK` |
| `http.post_root.header_names` | ordered | MISMATCH | 0.62 | `Date, Server, Allow, Content-Length, Content-Type` | `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, V...` |
| `http.post_root.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.post_root.header_values` | exact | MISMATCH | 0.12 | `{"date": "<http-date>", "allow": "POST,OPTIONS,HEAD,GET", "content-...` | `{"date": "<http-date>", "last-modified": "<http-date>", "etag": "<e...` |
| `http.post_root.body` | bytes | MISMATCH | 0.68 | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` | `\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "h...` |
| `http.post_root.closes` | exact | match | 1.00 | `false` | `false` |
| `http.delete_root.status_line` | exact | match | 1.00 | `HTTP/1.1 405 Method Not Allowed` | `HTTP/1.1 405 Method Not Allowed` |
| `http.delete_root.header_names` | ordered | match | 1.00 | `Date, Server, Allow, Content-Length, Content-Type` | `Date, Server, Allow, Content-Length, Content-Type` |
| `http.delete_root.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.delete_root.header_values` | exact | MISMATCH | 0.75 | `{"date": "<http-date>", "allow": "POST,OPTIONS,HEAD,GET", "content-...` | `{"date": "<http-date>", "allow": "GET,POST,OPTIONS,HEAD", "content-...` |
| `http.delete_root.body` | bytes | match | 1.00 | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` |
| `http.delete_root.closes` | exact | match | 1.00 | `false` | `false` |
| `http.unknown_method.status_line` | exact | match | 1.00 | `HTTP/1.1 501 Not Implemented` | `HTTP/1.1 501 Not Implemented` |
| `http.unknown_method.header_names` | ordered | match | 1.00 | `Date, Server, Allow, Content-Length, Connection, Content-Type` | `Date, Server, Allow, Content-Length, Connection, Content-Type` |
| `http.unknown_method.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.unknown_method.header_values` | exact | MISMATCH | 0.60 | `{"date": "<http-date>", "allow": "POST,OPTIONS,HEAD,GET", "content-...` | `{"date": "<http-date>", "allow": "GET,POST,OPTIONS,HEAD", "content-...` |
| `http.unknown_method.body` | bytes | MISMATCH | 1.00 | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` |
| `http.unknown_method.closes` | exact | match | 1.00 | `true` | `true` |
| `http.malformed_request_line.status_line` | exact | match | 1.00 | `HTTP/1.1 400 Bad Request` | `HTTP/1.1 400 Bad Request` |
| `http.malformed_request_line.header_names` | ordered | match | 1.00 | `Date, Server, Content-Length, Connection, Content-Type` | `Date, Server, Content-Length, Connection, Content-Type` |
| `http.malformed_request_line.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.malformed_request_line.header_values` | exact | MISMATCH | 0.75 | `{"date": "<http-date>", "content-length": "301", "connection": "clo...` | `{"date": "<http-date>", "content-length": "302", "connection": "clo...` |
| `http.malformed_request_line.body` | bytes | MISMATCH | 1.00 | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` |
| `http.malformed_request_line.closes` | exact | match | 1.00 | `true` | `true` |
| `http.http09_request.status_line` | exact | MISMATCH | 0.00 | `HTTP/1.1 200 OK` | `null` |
| `http.http09_request.header_names` | ordered | MISMATCH | 0.00 | `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, V...` | `(none)` |
| `http.http09_request.server` | exact | MISMATCH | 0.00 | `Apache/2.4.41 (Ubuntu)` | `null` |
| `http.http09_request.header_values` | exact | MISMATCH | 0.00 | `{"date": "<http-date>", "last-modified": "<http-date>", "etag": "<e...` | `{}` |
| `http.http09_request.body` | bytes | MISMATCH | 0.91 | `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "htt...` | `\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "h...` |
| `http.http09_request.closes` | exact | match | 1.00 | `true` | `true` |
| `http.no_host_http11.status_line` | exact | match | 1.00 | `HTTP/1.1 400 Bad Request` | `HTTP/1.1 400 Bad Request` |
| `http.no_host_http11.header_names` | ordered | match | 1.00 | `Date, Server, Content-Length, Connection, Content-Type` | `Date, Server, Content-Length, Connection, Content-Type` |
| `http.no_host_http11.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.no_host_http11.header_values` | exact | MISMATCH | 0.75 | `{"date": "<http-date>", "content-length": "301", "connection": "clo...` | `{"date": "<http-date>", "content-length": "302", "connection": "clo...` |
| `http.no_host_http11.body` | bytes | MISMATCH | 1.00 | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` |
| `http.no_host_http11.closes` | exact | match | 1.00 | `true` | `true` |
| `http.uri_9000.status_line` | exact | match | 1.00 | `HTTP/1.1 414 Request-URI Too Long` | `HTTP/1.1 414 Request-URI Too Long` |
| `http.uri_9000.header_names` | ordered | match | 1.00 | `Date, Server, Content-Length, Connection, Content-Type` | `Date, Server, Content-Length, Connection, Content-Type` |
| `http.uri_9000.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.uri_9000.header_values` | exact | MISMATCH | 0.75 | `{"date": "<http-date>", "content-length": "323", "connection": "clo...` | `{"date": "<http-date>", "content-length": "324", "connection": "clo...` |
| `http.uri_9000.body` | bytes | MISMATCH | 1.00 | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` |
| `http.uri_9000.closes` | exact | match | 1.00 | `true` | `true` |
| `http.uri_70000.status_line` | exact | match | 1.00 | `HTTP/1.1 414 Request-URI Too Long` | `HTTP/1.1 414 Request-URI Too Long` |
| `http.uri_70000.header_names` | ordered | match | 1.00 | `Date, Server, Content-Length, Connection, Content-Type` | `Date, Server, Content-Length, Connection, Content-Type` |
| `http.uri_70000.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.uri_70000.header_values` | exact | MISMATCH | 0.75 | `{"date": "<http-date>", "content-length": "323", "connection": "clo...` | `{"date": "<http-date>", "content-length": "324", "connection": "clo...` |
| `http.uri_70000.body` | bytes | MISMATCH | 1.00 | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` | `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<...` |
| `http.uri_70000.closes` | exact | match | 1.00 | `true` | `true` |
| `http.http10_no_headers.status_line` | exact | match | 1.00 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |
| `http.http10_no_headers.header_names` | ordered | match | 1.00 | `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, V...` | `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, V...` |
| `http.http10_no_headers.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.http10_no_headers.header_values` | exact | MISMATCH | 0.88 | `{"date": "<http-date>", "last-modified": "<http-date>", "etag": "<e...` | `{"date": "<http-date>", "last-modified": "<http-date>", "etag": "<e...` |
| `http.http10_no_headers.body` | bytes | MISMATCH | 0.91 | `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "htt...` | `\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "h...` |
| `http.http10_no_headers.closes` | exact | match | 1.00 | `true` | `true` |
| `http.connection_close.status_line` | exact | match | 1.00 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |
| `http.connection_close.header_names` | ordered | match | 1.00 | `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, V...` | `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, V...` |
| `http.connection_close.server` | exact | match | 1.00 | `Apache/2.4.41 (Ubuntu)` | `Apache/2.4.41 (Ubuntu)` |
| `http.connection_close.header_values` | exact | MISMATCH | 0.88 | `{"date": "<http-date>", "last-modified": "<http-date>", "etag": "<e...` | `{"date": "<http-date>", "last-modified": "<http-date>", "etag": "<e...` |
| `http.connection_close.body` | bytes | MISMATCH | 0.91 | `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "htt...` | `\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "h...` |
| `http.connection_close.closes` | exact | match | 1.00 | `true` | `true` |
| `http.keep_alive.second_request_answered` | exact | match | 1.00 | `true` | `true` |
| `http.keep_alive.connection_header` | exact | match | 1.00 | `null` | `null` |
| `http.response_latency` | timing | within tolerance | 0.17 | `0.006` | `0.001` |
