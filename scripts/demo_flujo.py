"""
Recorre el flujo completo contra un servidor en marcha, como lo haria un
integrador de verdad mas un firmante humano.

    python -m uvicorn app.main:app --port 8000      # en una terminal
    python -m scripts.demo_flujo                    # en otra
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

BASE = "http://127.0.0.1:8000"


def csrf_de(html: str) -> str:
    encontrado = re.search(r'name="csrf" value="([^"]+)"', html)
    if not encontrado:
        raise SystemExit("No se encontro el token csrf en la pagina")
    return encontrado.group(1)


def paso(numero: int, texto: str) -> None:
    print(f"\n{numero}. {texto}")


def main(client_id: str, client_secret: str) -> None:
    api = httpx.Client(base_url=BASE, auth=(client_id, client_secret), timeout=30)
    navegador = httpx.Client(base_url=BASE, follow_redirects=True, timeout=30)

    paso(1, "El integrador crea el contrato (plantilla + variables + firmantes)")
    respuesta = api.post(
        "/v1/contratos",
        headers={"Idempotency-Key": "demo-001"},
        json={
            "plantilla": "contrato_servicio",
            "referencia_externa": "SOL-839291",
            "firmantes": [
                {"rol": "CLIENTE", "nombre": "Juan Perez",
                 "documento": "40221182617", "email": "juan@example.com"},
                {"rol": "EMPRESA", "nombre": "Ana Gomez",
                 "documento": "40221182617", "email": "ana@acme.com"},
            ],
            "variables": {
                "cliente": {"nombre": "Juan Perez", "cedula": "402-2118261-7",
                            "direccion": "Av. Winston Churchill 1099, Santo Domingo"},
                "servicio": {"nombre": "Plan Premium", "precio": "12500",
                             "meses": 12, "inicio": "2026-10-01"},
            },
        },
    )
    respuesta.raise_for_status()
    contrato = respuesta.json()
    print(f"   contrato   {contrato['contract_id']}")
    print(f"   estado     {contrato['status']}")
    print(f"   hash doc   {contrato['document_hash'][:32]}...")
    print(f"   url firma  {contrato['signing_url']}")

    paso(2, "El cliente abre el enlace y pide su codigo")
    token = contrato["signing_url"].rstrip("/").split("/")[-1]
    pagina = navegador.get(f"/firma/{token}")
    envio = navegador.post(f"/firma/{token}/codigo", data={"csrf": csrf_de(pagina.text)})
    print("   codigo enviado (mira la consola del servidor para verlo)")
    codigo = input("   escribe el codigo que aparecio en el servidor: ").strip()

    paso(3, "El cliente se identifica, lee el documento y firma")
    verif = navegador.post(
        f"/firma/{token}/verificar", data={"csrf": csrf_de(envio.text), "codigo": codigo}
    )
    if "no coincide" in verif.text or "vencio" in verif.text:
        raise SystemExit("   el codigo no fue aceptado")
    navegador.post(f"/firma/{token}/firmar", data={"csrf": csrf_de(verif.text), "acepto": "si"})
    estado = api.get(f"/v1/contratos/{contrato['contract_id']}").json()
    print(f"   estado ahora: {estado['status']}")

    if estado["status"] == "PENDIENTE_EMPRESA":
        paso(4, "Le toca al representante de la empresa")
        reenvio = api.post(f"/v1/contratos/{contrato['contract_id']}/reenviar").json()
        token2 = reenvio["signing_url"].rstrip("/").split("/")[-1]
        pagina = navegador.get(f"/firma/{token2}")
        envio = navegador.post(f"/firma/{token2}/codigo", data={"csrf": csrf_de(pagina.text)})
        codigo2 = input("   escribe el segundo codigo: ").strip()
        verif = navegador.post(
            f"/firma/{token2}/verificar", data={"csrf": csrf_de(envio.text), "codigo": codigo2}
        )
        navegador.post(f"/firma/{token2}/firmar", data={"csrf": csrf_de(verif.text), "acepto": "si"})

    paso(5, "Resultado final")
    final = api.get(f"/v1/contratos/{contrato['contract_id']}").json()
    print(f"   estado          {final['status']}")
    print(f"   hash documento  {final['final_document_hash']}")

    documento = api.get(f"/v1/contratos/{contrato['contract_id']}/documento")
    salida = Path("contrato-final.html")
    salida.write_bytes(documento.content)
    print(f"   documento final guardado en {salida.resolve()}")

    auditoria = api.get(f"/v1/contratos/{contrato['contract_id']}/auditoria").json()
    print(f"   cadena integra  {auditoria['chain']['integra']}")
    print(f"   eventos         {len(auditoria['events'])}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Uso: python -m scripts.demo_flujo <client_id> <client_secret>")
    main(sys.argv[1], sys.argv[2])
