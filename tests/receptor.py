"""Un receptor de webhooks de mentira, para comprobar la entrega real."""
from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer


class Receptor:
    def __init__(self, puerto: int) -> None:
        self.puerto = puerto
        self.entregas: list[dict] = []

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.puerto}/hook"

    def esperar(self, cuantas: int, segundos: float = 5.0) -> None:
        limite = time.time() + segundos
        while time.time() < limite and len(self.entregas) < cuantas:
            time.sleep(0.05)


@contextmanager
def receptor_webhook():
    receptor = Receptor(0)

    class Manejador(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            largo = int(self.headers.get("content-length", 0))
            crudo = self.rfile.read(largo).decode("utf-8")
            receptor.entregas.append({
                "crudo": crudo,
                "cuerpo": json.loads(crudo),
                "firma": self.headers.get("x-signature"),
                "marca": self.headers.get("x-timestamp"),
                "evento_id": self.headers.get("x-event-id"),
            })
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    servidor = HTTPServer(("127.0.0.1", 0), Manejador)
    receptor.puerto = servidor.server_address[1]
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        yield receptor
    finally:
        servidor.shutdown()
        servidor.server_close()
