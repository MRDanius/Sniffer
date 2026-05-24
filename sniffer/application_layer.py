from sniffer.packet import IPPROTO_TCP


HTTP_PORTS = (80, 8080)
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
REQUEST_HEADERS = ("Host", "Content-Type", "Content-Length", "User-Agent")
RESPONSE_HEADERS = ("Content-Type", "Content-Length", "Server")


def parse_http(packet):
    if packet.proto != IPPROTO_TCP:
        return None

    if packet.src_port not in HTTP_PORTS and packet.dst_port not in HTTP_PORTS:
        return None

    if not packet.payload:
        return None

    text = packet.payload.decode("utf-8", errors="replace")
    lines = text.splitlines()

    if not lines:
        return None

    first_line = lines[0]

    if _is_http_request(first_line):
        parts = first_line.split()
        headers = _parse_headers(lines[1:])

        return {
            "type": "request",
            "method": parts[0],
            "path": parts[1],
            "version": parts[2],
            "headers": _interesting_headers(headers, REQUEST_HEADERS),
        }

    if _is_http_response(first_line):
        parts = first_line.split(" ", 2)
        headers = _parse_headers(lines[1:])
        reason = ""

        if len(parts) == 3:
            reason = parts[2]

        return {
            "type": "response",
            "version": parts[0],
            "status": parts[1],
            "reason": reason,
            "headers": _interesting_headers(headers, RESPONSE_HEADERS),
        }

    return None


def _is_http_request(line):
    parts = line.split()

    return (
        len(parts) >= 3
        and parts[0] in HTTP_METHODS
        and parts[2].startswith("HTTP/")
    )


def _is_http_response(line):
    parts = line.split(" ", 2)

    return len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit()


def _parse_headers(lines):
    headers = {}

    for line in lines:
        if line == "":
            break

        if ":" not in line:
            continue

        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    return headers


def _interesting_headers(headers, names):
    result = {}

    for name in names:
        value = headers.get(name.lower())
        if value is not None:
            result[name] = value

    return result
