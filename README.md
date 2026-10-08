# Simulador Python de Java Keytool

Práctica UF3: simulador CLI de las funciones esenciales de `keytool`. El proyecto genera claves RSA de 2048 bits, guarda las claves privadas en un almacén cifrado y crea solicitudes CSR PEM.

## Integrantes

- Nombre y apellidos del/de la integrante 1: **[Completar]**
- Nombre y apellidos del/de la integrante 2: **[Completar]**

## Requisitos e instalación

- Python 3.10 o posterior.
- `pip`.

```console
python -m venv .venv
```

En Windows PowerShell, activa el entorno virtual con `.\.venv\Scripts\Activate.ps1`; en macOS/Linux, usa `source .venv/bin/activate`. Después, instala la dependencia:

```console
python -m pip install -r requirements.txt
```

La dependencia principal indicada en el enunciado también se puede instalar directamente con `pip install cryptography`.

## Uso

La ayuda muestra los comandos y opciones disponibles:

```console
python mykeytool.py --help
```

Crear el almacén y generar una clave. La primera ejecución solicita dos veces la contraseña del almacén; después pregunta el alias, los seis componentes del Distinguished Name y dos veces la contraseña propia de la clave:

```console
python mykeytool.py --genkey
```

El almacén se guarda por defecto como `keystore.pystore` en la carpeta actual. Se puede elegir otra ruta con `--store`:

```console
python mykeytool.py --genkey --store datos/mi-almacen.pystore
```

Crear una solicitud CSR para una clave guardada. Se solicitan la contraseña del almacén, el alias y la contraseña privada de ese alias. El resultado es `<alias>.csr` en formato PEM:

```console
python mykeytool.py --certreq
python mykeytool.py --certreq --store datos/mi-almacen.pystore
```

Los alias solo admiten letras, números, punto, guion y guion bajo. Las contraseñas deben tener al menos ocho caracteres. No se guardan contraseñas en texto claro: el almacén usa Fernet con una clave derivada mediante PBKDF2-HMAC-SHA256, y cada clave privada también está cifrada con la contraseña de su alias.

## Pruebas

Ejecutar las pruebas automatizadas:

```console
python -m unittest discover -s tests -v
```

| Prueba | Resultado esperado | Resultado ejecutado |
|---|---|---|
| Mostrar ayuda con `--help` | Lista `--genkey`, `--certreq` y `--store` | OK, comprobación manual |
| Guardar y leer el almacén | Se recuperan los datos originales | OK, prueba automatizada |
| Contraseña maestra errónea | Mensaje de contraseña incorrecta o almacén alterado; sin traceback | OK, prueba automatizada |
| Archivo inexistente o malformado | Mensaje de almacén no encontrado/dañado; sin traceback | OK, prueba automatizada |
| Alias duplicado | La operación se rechaza y el almacén no se sobrescribe | OK, prueba automatizada |
| Contraseña de alias errónea | Se informa del error y no se genera la CSR | OK, prueba automatizada |
| Generar clave RSA y CSR | RSA de 2048 bits y CSR PEM verificable | OK, prueba automatizada |
| Alias con separadores de ruta | Se rechaza antes de usarlo como nombre de archivo | OK, prueba automatizada |

## Limitaciones

Este es un formato de almacén didáctico propio (`.pystore`), no es compatible con los almacenes Java JKS/PKCS12 ni sustituye a `keytool` para uso de producción. Si una contraseña maestra es incorrecta o se ha alterado el texto cifrado, ambos casos se notifican juntos porque no se puede distinguirlos de forma fiable sin exponer información del almacén.