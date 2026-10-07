#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
LABORATORIO 1: INVENTARIO, ESTADO Y CONFIGURACIÓN SEGURA CON NETMIKO
================================================================================
Curso:        ITIEL-13 - Redes Programables (UTN)

FLUJO:
  1. Lee inventario.yaml (equipos + número de lista del estudiante).
  2. Por cada equipo: conecta por SSH (Netmiko), recolecta el estado y lo
     convierte a diccionarios (R4). Si un equipo falla, se registra y sigue (R3).
  3. En equipos con rol 'escritura' asegura lo-ssh-<N> con 10.253.0.<N>/32
     sin duplicar nada (R6). Con --limpiar elimina solo esos objetos.
  4. Escribe reporte_estado.json y muestra una tabla resumen (R5).

USO:
    export LAB_PASS_MT_LAB='...'          # opcional; si no, se pide con getpass
    python lab1_inventario.py             # estado + cambio idempotente
    python lab1_inventario.py --limpiar   # elimina solo mis objetos
================================================================================
"""

import argparse
import getpass
import json
import os
import re
from datetime import datetime
from pathlib import Path

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

BASE = Path(__file__).resolve().parent
INVENTARIO = BASE / "inventario.yaml"
REPORTE = BASE / "reporte_estado.json"
LOGS = BASE / "logs"

# ==============================================================================
# R4. COMANDOS POR device_type (agregar un fabricante = agregar una entrada)
# ==============================================================================
COMANDOS = {
    "mikrotik_routeros": {
        # ':put [... get name]': en RouterOS 7.24 el 'print' sale partido letra por letra
        "identidad": ":put [/system identity get name]",
        "uptime": "/system resource print",
        "interfaces": "/ip address print terse",
        "gateway": "/ip route print terse where dst-address=0.0.0.0/0",
    },
    "cisco_ios": {
        "identidad": "show running-config | include hostname",
        "uptime": "show version | include uptime",
        "interfaces": "show ip interface brief",
        "gateway": "show ip route 0.0.0.0",
    },
}


# ==============================================================================
# PARSERS: texto -> diccionarios
# ==============================================================================
def texto_a_dict(salida):
    """Convierte líneas 'clave: valor' (ej. /system resource print) en un diccionario."""
    datos = {}
    for linea in salida.splitlines():
        if ":" in linea:
            clave, valor = linea.split(":", 1)
            datos[clave.strip()] = valor.strip()
    return datos


def terse_a_dicts(salida):
    """Convierte la salida 'print terse' de RouterOS (una línea por registro) en lista de dicts.

    Los valores pueden traer espacios sin comillas (comment=usuario Lab1), así que se
    corta en cada ' clave=' en lugar de usar split() simple.
    """
    registros = []
    for linea in salida.splitlines():
        linea = linea.strip()
        if "=" not in linea:
            continue
        claves = list(re.finditer(r"(?:^|\s)([a-z0-9-]+)=", linea))
        reg = {"flags": linea[: claves[0].start()].split()[1:] if claves else []}
        for i, m in enumerate(claves):
            fin = claves[i + 1].start() if i + 1 < len(claves) else len(linea)
            reg[m.group(1)] = linea[m.end():fin].strip().strip('"')
        registros.append(reg)
    return registros


def parse_mikrotik(salidas):
    recursos = texto_a_dict(salidas["uptime"])
    interfaces = [
        {"interfaz": r.get("interface"), "ip": r.get("address"), "comentario": r.get("comment", "")}
        for r in terse_a_dicts(salidas["interfaces"])
    ]
    rutas = terse_a_dicts(salidas["gateway"])
    return {
        "identidad": salidas["identidad"].strip(),
        "uptime": recursos.get("uptime"),
        "version": recursos.get("version"),
        "interfaces": interfaces,
        "gateway": rutas[0].get("gateway") if rutas else None,
    }


def parse_cisco(salidas):
    m = re.search(r"hostname\s+(\S+)", salidas["identidad"])
    up = re.search(r"uptime is (.+)", salidas["uptime"])
    interfaces = []
    for linea in salidas["interfaces"].splitlines()[1:]:
        campos = linea.split()
        if len(campos) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", campos[1]):
            interfaces.append({"interfaz": campos[0], "ip": campos[1], "estado": campos[4] if len(campos) > 4 else ""})
    gw = re.search(r"\*\s*(\d+\.\d+\.\d+\.\d+)", salidas["gateway"])
    return {
        "identidad": m.group(1) if m else None,
        "uptime": up.group(1).strip() if up else None,
        "interfaces": interfaces,
        "gateway": gw.group(1) if gw else None,
    }


PARSERS = {"mikrotik_routeros": parse_mikrotik, "cisco_ios": parse_cisco}


# ==============================================================================
# R1 / R2. INVENTARIO Y CREDENCIALES
# ==============================================================================
def cargar_inventario(ruta=INVENTARIO):
    with open(ruta, encoding="utf-8") as f:
        inv = yaml.safe_load(f)
    for eq in inv["equipos"]:
        faltan = {"nombre", "host", "device_type", "usuario", "rol"} - eq.keys()
        if faltan:
            raise ValueError(f"Equipo {eq.get('nombre', '?')} sin campos: {', '.join(sorted(faltan))}")
    return inv


def obtener_clave(nombre, usuario):
    """LAB_PASS_<NOMBRE> (mayúsculas, '-' -> '_'); si no existe, getpass."""
    variable = "LAB_PASS_" + nombre.upper().replace("-", "_")
    return os.getenv(variable) or getpass.getpass(f"Clave de '{usuario}' en {nombre} ({variable} no definida): ")


# ==============================================================================
# R6. CAMBIO SIN DUPLICADOS (MikroTik)
# ==============================================================================
def asegurar_loopback(conn, numero, nombre_est):
    """Crea lo-ssh-N y 10.253.0.N/32 solo si faltan. Devuelve lista de acciones."""
    bridge, ip = f"lo-ssh-{numero}", f"10.253.0.{numero}/32"
    comentario = f"Lab1 {nombre_est}"
    acciones = []

    # 1) Consultar antes de crear: bridge
    existe = terse_a_dicts(conn.send_command(f"/interface bridge print terse where name=\"{bridge}\""))
    if not existe:
        conn.send_command(f'/interface bridge add name={bridge} protocol-mode=none comment="{comentario}"')
        acciones.append(f"creado bridge {bridge}")
    elif existe[0].get("comment") != comentario:
        conn.send_command(f'/interface bridge set [find name=\"{bridge}\"] comment="{comentario}"')
        acciones.append(f"comentario de {bridge} actualizado")

    # 2) Consultar antes de crear: IP (buscada por dirección, en cualquier interfaz)
    ips = terse_a_dicts(conn.send_command(f"/ip address print terse where address=\"{ip}\""))
    if not ips:
        conn.send_command(f'/ip address add address={ip} interface={bridge} comment="{comentario}"')
        acciones.append(f"asignada {ip} a {bridge}")
    elif ips[0].get("interface") != bridge:
        # Está en otra interfaz: no es nuestro objeto, no se toca
        raise RuntimeError(f"{ip} ya existe en {ips[0].get('interface')}; no se modifica")

    # 3) Verificar con lectura después del cambio
    ok_bridge = terse_a_dicts(conn.send_command(f"/interface bridge print terse where name=\"{bridge}\""))
    ok_ip = terse_a_dicts(conn.send_command(f"/ip address print terse where address=\"{ip}\" and interface=\"{bridge}\""))
    verificado = bool(ok_bridge and ok_ip)
    return {"objeto": f"{bridge} {ip}", "acciones": acciones or ["sin cambios"], "verificado": verificado}


def limpiar_loopback(conn, numero):
    """Elimina solo lo-ssh-N y su IP (filtrando por nombre propio)."""
    bridge, ip = f"lo-ssh-{numero}", f"10.253.0.{numero}/32"
    acciones = []
    if terse_a_dicts(conn.send_command(f"/ip address print terse where address=\"{ip}\" and interface=\"{bridge}\"")):
        conn.send_command(f"/ip address remove [find address=\"{ip}\" and interface=\"{bridge}\"]")
        acciones.append(f"eliminada {ip}")
    if terse_a_dicts(conn.send_command(f"/interface bridge print terse where name=\"{bridge}\"")):
        conn.send_command(f"/interface bridge remove [find name=\"{bridge}\"]")
        acciones.append(f"eliminado bridge {bridge}")
    quedan = terse_a_dicts(conn.send_command(f"/interface bridge print terse where name=\"{bridge}\""))
    return {"objeto": f"{bridge} {ip}", "acciones": acciones or ["sin cambios"], "verificado": not quedan}


# ==============================================================================
# R3. PROCESAR UN EQUIPO (conexión robusta)
# ==============================================================================
def procesar_equipo(eq, estudiante, limpiar):
    resultado = {
        "nombre": eq["nombre"],
        "host": eq["host"],
        "device_type": eq["device_type"],
        "rol": eq["rol"],
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "estado": "ok",
        "datos": None,
        "cambio": None,
    }
    dispositivo = {
        "device_type": eq["device_type"],
        "host": eq["host"],
        "username": eq["usuario"],
        "password": obtener_clave(eq["nombre"], eq["usuario"]),
        "port": eq.get("puerto", 22),
        "session_log": str(LOGS / f"{eq['nombre']}.log"),
        "conn_timeout": 15,
    }
    try:
        with ConnectHandler(**dispositivo) as conn:
            comandos = COMANDOS[eq["device_type"]]
            salidas = {dato: conn.send_command(cmd, read_timeout=20) for dato, cmd in comandos.items()}
            resultado["datos"] = PARSERS[eq["device_type"]](salidas)

            if eq["rol"] == "escritura" and eq["device_type"] == "mikrotik_routeros":
                if limpiar:
                    resultado["cambio"] = limpiar_loopback(conn, estudiante["numero"])
                else:
                    resultado["cambio"] = asegurar_loopback(conn, estudiante["numero"], estudiante["nombre"])
    except NetmikoTimeoutException:
        resultado["estado"] = f"error: timeout, {eq['host']} no responde"
    except NetmikoAuthenticationException:
        resultado["estado"] = f"error: autenticación rechazada para '{eq['usuario']}'"
    except Exception as e:
        resultado["estado"] = f"error: {e}"
    return resultado


# ==============================================================================
# R5. REPORTE
# ==============================================================================
def imprimir_tabla(resultados):
    fila = "{:<12} {:<15} {:<40} {:>6}  {:<15}"
    print("\n" + fila.format("EQUIPO", "IP", "ESTADO", "IFACES", "GATEWAY"))
    print("-" * 92)
    for r in resultados:
        d = r["datos"] or {}
        print(fila.format(r["nombre"], r["host"], r["estado"][:40],
                          len(d.get("interfaces", [])) if d else "-", d.get("gateway") or "-"))
    for r in resultados:
        if r["cambio"]:
            c = r["cambio"]
            print(f"\n[{r['nombre']}] {c['objeto']}: {', '.join(c['acciones'])} "
                  f"(verificado: {'sí' if c['verificado'] else 'NO'})")


def main():
    parser = argparse.ArgumentParser(description="Lab 1: inventario, estado y cambio idempotente")
    parser.add_argument("--limpiar", action="store_true", help="elimina solo lo-ssh-<N> y su IP")
    parser.add_argument("-i", "--inventario", default=INVENTARIO, help="ruta del inventario YAML")
    args = parser.parse_args()

    LOGS.mkdir(exist_ok=True)
    inv = cargar_inventario(args.inventario)
    resultados = []
    for eq in inv["equipos"]:
        print(f"[*] Procesando {eq['nombre']} ({eq['host']})...")
        resultados.append(procesar_equipo(eq, inv["estudiante"], args.limpiar))

    with open(REPORTE, "w", encoding="utf-8") as f:
        json.dump({"generado": datetime.now().isoformat(timespec="seconds"), "equipos": resultados},
                  f, indent=2, ensure_ascii=False)
    imprimir_tabla(resultados)
    print(f"\n[✔] Reporte: {REPORTE.name}   Logs: {LOGS.name}/")


if __name__ == "__main__":
    main()
