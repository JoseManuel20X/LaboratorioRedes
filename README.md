# Laboratorio 1 — Inventario, estado y configuración segura con Netmiko

ITIEL-13 Redes Programables (UTN). El script `lab1_inventario.py` lee `inventario.yaml`, se conecta
por SSH (Netmiko) a cada equipo, guarda su estado como JSON y asegura en el MikroTik la interfaz
`lo-ssh-<N>` con `10.253.0.<N>/32` sin duplicar nada.

## Instalación

```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

`paramiko<4` es necesario para el extra multivendor: el Cisco 3725 (IOS 12.4) solo ofrece
`diffie-hellman-group1-sha1` y `ssh-rsa`, que paramiko 4 y posteriores eliminaron.

## Configuración

1. En `inventario.yaml`, ajuste `estudiante.numero` (su número de lista N) y `estudiante.nombre`.
2. Las contraseñas **no** van en el código ni en el YAML. Se leen de `LAB_PASS_<NOMBRE>`
   (nombre en mayúsculas, `-` → `_`); si la variable no existe, el script la pide con `getpass`:

```bash
export LAB_PASS_MT_LAB='********'      # equipo mt-lab
export LAB_PASS_CISCO_LAB='********'   # equipo cisco-lab
```

## Ejecución

```bash
python lab1_inventario.py              # estado + cambio idempotente en el MikroTik
python lab1_inventario.py              # 2.ª vez: "sin cambios"
python lab1_inventario.py --limpiar    # elimina solo lo-ssh-<N> y su IP
```

Salidas:
- `reporte_estado.json`: por equipo, la fecha, el estado (`ok` o el mensaje de error), los datos (identidad,
  uptime, interfaces con IP, gateway por defecto) y el resultado del cambio.
- `logs/<equipo>.log`: el `session_log` de Netmiko de cada equipo.
- Consola: una tabla con equipo, IP, estado, cantidad de interfaces y gateway.

Para probar el manejo de errores: `export LAB_PASS_MT_LAB=mala`. El equipo queda con `error: autenticación…` y
el script continúa con el siguiente.

## Diseño

| Requerimiento | Implementación |
|---|---|
| R1 | `cargar_inventario()` valida los campos `nombre, host, device_type, usuario, rol` |
| R2 | `obtener_clave()`: `LAB_PASS_<NOMBRE>` → `getpass` |
| R3 | `ConnectHandler` en `with`; captura Timeout, Auth y `Exception` por equipo; `session_log` en `logs/` |
| R4 | `COMANDOS[device_type]` + `PARSERS[device_type]`; `terse_a_dicts()` para `print terse` |
| R5 | `reporte_estado.json` + `imprimir_tabla()` |
| R6 | `asegurar_loopback()` consulta, crea solo si falta y verifica; `limpiar_loopback()` filtra por su nombre y su IP |
| Extra | Cisco IOS en el inventario (`cisco_ios`, solo lectura) |

Nota RouterOS: en los filtros `where` y `find`, los valores con `/` deben ir entre comillas
(`where address="10.253.0.N/32"`). Sin comillas el filtro devuelve vacío y el script volvería a crear la IP.

## Laboratorio local en GNS3

Réplica del escenario en el proyecto `Lab1` de GNS3:
- Cloud1 (`tap0`, 10.60.30.1/24) → Switch1
- MikroTik CHR 7.24.4: `ether1` 10.60.30.202/24, `ether2` 192.168.20.1/24 (PC2 192.168.20.10)
- Cisco 3725: `Fa0/0` 10.60.30.203/24, `Fa0/1` 192.168.10.1/24 (PC1 192.168.10.10)

## Declaración de uso de IA

Se usó Claude (Anthropic) como asistente para montar la topología de GNS3, para la estructura inicial
del script y los parsers, y para depurar el filtro de RouterOS y la compatibilidad SSH con IOS 12.4.
El código fue revisado y probado por el estudiante.
