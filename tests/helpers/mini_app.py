import http.server
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    porta = int(sys.argv[1])
    servidor = http.server.HTTPServer(("127.0.0.1", porta), Handler)
    servidor.serve_forever()
