# Simulador Python de Java Keytool (CLI)

Proyecto de simulación en Python de las funcionalidades esenciales de la herramienta oficial `keytool` de Java (UF3 / M2 Criptografía y Seguridad). Permite generar pares de claves asimétricas RSA de 2048 bits, gestionar almacenes cifrados multicapa mediante PBKDF2 y Fernet, emitir certificados autofirmados X.509 y generar solicitudes de firma de certificados (CSR) en formato PEM.

---

## 1. Integrantes del Proyecto

- **Nil Rivera Bonet** (`nilrivbon@campus.monlau.com`)
- **Arnau Pousa** (`pousa.arnau@gmail.com`)

---

## 2. Requisitos e Instalación

- **Python**: 3.10 o superior.
- **Librería principal**: `cryptography` (estándar industrial para operaciones criptográficas y X.509).

### Creación del Entorno Virtual e Instalación de Dependencias

1. Crear el entorno virtual:
   ```bash
   python -m venv .venv
   ```

2. Activar el entorno virtual:
   - **Windows (PowerShell)**:
     ```powershell
     .\.venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS**:
     ```bash
     source .venv/bin/activate
     ```

3. Instalar la librería requerida:
   ```bash
   pip install cryptography
   ```
   *(o alternativamente: `pip install -r requirements.txt`)*

---

## 3. Fundamento Criptográfico y Arquitectura de Seguridad

De acuerdo con el manual de teoría del módulo y las especificaciones oficiales de Java Keytool:
- **Cifrado Simétrico del Almacén**: Se utiliza derivación de claves mediante **PBKDF2-HMAC-SHA256** con una sal criptográfica aleatoria de 16 bytes (`os.urandom(16)`) y **600.000 iteraciones** (recomendación de OWASP contra ataques de fuerza bruta). El contenido se protege con **Fernet** (cifrado autenticado AES-128-CBC + HMAC-SHA256).
- **Doble Nivel de Seguridad (Contraseña del Almacén vs. Contraseña del Alias)**:
  1. *Contraseña del Almacén (KeyStore)*: Desbloquea y autentica el contenedor completo.
  2. *Contraseña de la Clave Privada (Alias)*: Cada clave privada RSA se almacena cifrada individualmente bajo el estándar **PKCS#8** con algoritmo `BestAvailableEncryption` (AES-256-CBC).
- **Reglas y Restricciones Estrictas de Contraseñas (Keytool)**:
  * **Longitud mínima**: 6 caracteres exactos. Si se introduce una longitud de 1 a 5 caracteres, la herramienta rechaza la entrada devolviendo el mensaje oficial: *"Keystore password is too short - must be at least 6 characters"*.
  * **Espacios y caracteres**: Permite espacios en blanco intermedios o contraseñas compuestas únicamente de espacios, así como cualquier carácter Unicode válido.
- **Criptografía Asimétrica y Algoritmos**: Pares de claves **RSA de 2048 bits** con exponente público estándar $e = 65537$ y algoritmo de firma digital **SHA256withRSA** (SHA-256 con RSA).
- **Validez del Certificado**: Por defecto, los certificados autofirmados X.509 v3 se emiten con **90 días de validez** (valor estándar del modificador `-validity` en Java Keytool).
- **Alias y Convenciones**: El alias por defecto es **`mykey`** (si se omite o se pulsa Enter en blanco) y es insensible a mayúsculas/minúsculas como en los formatos estándar PKCS12/JKS.
- **Nombre Distinguido (DName)**: Admite omitir campos opcionales; el Common Name (CN) y los campos vacíos toman el valor por defecto literal **`Unknown`**, normalizando el código de país (C) a 2 letras mayúsculas ISO 3166-1.
- **Persistencia Atómica**: La escritura del archivo de almacén se realiza a través de un archivo temporal y reemplazo atómico (`os.replace`) para evitar corrupción en caso de interrupción.

---

## 4. Guía de Uso de la CLI y Ejemplos de Consola

### 4.1. Muestreo de Ayuda (`--help`)
```console
$ python mykeytool.py --help
usage: mykeytool.py [-h] (--genkey | --certreq | --list | --exportcert | --printcert | --delete)
                    [--store STORE] [--alias ALIAS] [--file FILE]

Simulador Python de Java Keytool: crea almacenes cifrados, claves RSA, certificados y solicitudes CSR.

options:
  -h, --help            show this help message and exit
  --genkey, --genkeypair
                        Genera un par de claves RSA de 2048 bits con certificado autofirmado y lo almacena.
  --certreq             Genera una solicitud de firma de certificado CSR en formato PEM.
  --list                [Ampliación] Muestra el listado de alias, tipo de entrada y huellas digitales del KeyStore.
  --exportcert, --export
                        [Ampliación] Exporta el certificado X.509 de un alias a un archivo .crt.
  --printcert           [Ampliación] Imprime la información criptográfica de un certificado (.crt) o solicitud (.csr).
  --delete              [Ampliación] Elimina un alias del KeyStore de forma segura.
  --store, --keystore STORE
                        Ruta del almacén cifrado (por defecto: keystore.pystore).
  --alias ALIAS         Alias de la clave (opcional; si se omite o se deja en blanco, el valor por defecto es 'mykey').
  --file FILE           Ruta de archivo de entrada o salida (para --certreq, --exportcert o --printcert).
```

---

### 4.2. Generación de Par de Claves y Almacén (`--genkeypair` o `--genkey`)
Crea un nuevo almacén (o actualiza uno existente), solicita los datos del titular (**Distinguished Name**) y genera el par de claves RSA de 2048 bits junto a un certificado autofirmado X.509 válido por 90 días.

```console
$ python mykeytool.py --genkeypair
Contraseña nueva del KeyStore: ******
Confirma la contraseña del KeyStore: ******
Alias de la clave [mykey]: servidor-web
Nombre y apellidos o nombre común (CN) [Unknown]: monlau.es
Nombre de la unidad organizativa (OU) [Unknown]: Informatica
Nombre de la organización (O) [Unknown]: Monlau Formacio
Nombre de la ciudad o localidad (L) [Unknown]: Barcelona
Nombre del estado o provincia (ST) [Unknown]: Barcelona
Código de país de dos letras (C) [Unknown]: ES
Contraseña nueva del alias 'servidor-web': ******
Confirma la contraseña del alias 'servidor-web': ******
Par RSA de 2048 bits guardado con el alias 'servidor-web' en keystore.pystore.
```

---

### 4.3. Generación de Solicitud de Firma de Certificado (`--certreq`)
Recupera la clave privada del alias indicado y genera un archivo `.csr` en formato PEM listo para ser firmado por una Autoridad de Certificación (CA).

```console
$ python mykeytool.py --certreq
Contraseña del KeyStore: ********
Alias de la clave: servidor-web
Contraseña del alias 'servidor-web': ********
Solicitud CSR creada: servidor-web.csr
```

El archivo resultante `servidor-web.csr` contiene:
```
-----BEGIN CERTIFICATE REQUEST-----
MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCRVMxEjAQBgNVBAgMCUJhcmNlbG9uYTES
...
-----END CERTIFICATE REQUEST-----
```

---

### 4.4. Listado de Entradas del Almacén (`--list`) - *[Ampliación]*
Muestra un resumen detallado de las claves almacenadas, propietarios y huellas digitales SHA-256, emulando la salida de `keytool -list -v` en Java.

```console
$ python mykeytool.py --list
Contraseña del KeyStore: ********

Tipo de almacén: PYSTORE (Simulador Java Keytool)
Almacén: keystore.pystore
El almacén contiene 1 entrada(s):

Nombre de alias: servidor-web
Tipo de entrada: ClavePrivada (PrivateKeyEntry)
Propietario (DName): CN=monlau.es, OU=Informatica, O=Monlau Formacio, L=Barcelona, ST=Barcelona, C=ES
Certificado autofirmado: Válido hasta 15/10/2027
Huella digital SHA-256: 4C:92:2F:E5:A2:80:7B:09:A6:61:52:1D:95:48:38:B0:...
--------------------------------------------------
```

---

### 4.5. Exportación de Certificado Digital (`--exportcert` o `--export`) - *[Ampliación]*
Exporta el certificado digital público X.509 asociado al alias en un archivo `.crt` independiente para su distribución o instalación en navegadores y sistemas operativos.

```console
$ python mykeytool.py --exportcert --alias servidor-web
Contraseña del KeyStore: ********
Certificado exportado en: servidor-web.crt
```

---

### 4.6. Inspección de Certificados y Solicitudes (`--printcert`) - *[Ampliación]*
Permite analizar e imprimir los campos criptográficos de un archivo `.crt` o `.csr` sin necesidad de contraseña del almacén.

```console
$ python mykeytool.py --printcert --file servidor-web.crt

Archivo: servidor-web.crt
Propietario (Subject):   CN=monlau.es,OU=Informatica,O=Monlau Formacio,L=Barcelona,ST=Barcelona,C=ES
Emisor (Issuer):         CN=monlau.es,OU=Informatica,O=Monlau Formacio,L=Barcelona,ST=Barcelona,C=ES
Número de serie:         48F0A2B19C0E24D9
Válido desde:            15/10/2026 15:50:00 UTC hasta: 15/10/2027 15:50:00 UTC
Algoritmo de clave:      RSA (2048 bits)
Algoritmo de firma:      SHA256 con RSA
Huellas digitales del certificado:
     SHA-256: 4C:92:2F:E5:A2:80:7B:09:A6:61:52:1D:95:48:38:B0:...
     SHA-1:   91:02:AE:65:4F:21:88:C1:2B:10:...
```

---

### 4.7. Eliminación Segura de Alias (`--delete`) - *[Ampliación]*
Permite dar de baja un par de claves con confirmación previa:

```console
$ python mykeytool.py --delete --alias servidor-web
Contraseña del KeyStore: ********
¿Desea realmente eliminar la entrada con el alias 'servidor-web'? (s/n): s
La entrada con alias 'servidor-web' ha sido eliminada del almacén.
```

---

## 5. Matriz de Pruebas Ejecutadas

Las pruebas se ejecutan mediante el framework nativo `unittest`:

```console
python -m unittest discover -s tests -v
```

| # | Caso de Prueba | Entrada / Condición | Comportamiento Esperado | Resultado |
|:--|:---|:---|:---|:---:|
| 1 | **Ayuda CLI** | `python mykeytool.py --help` | Lista todos los comandos, parámetros y descripciones | **OK** |
| 2 | **Creación y lectura almacén** | Datos válidos y contraseña correcta | Se serializa y descifra íntegramente (round-trip) | **OK** |
| 3 | **Contraseña incorrecta almacén** | Contraseña errónea en `load_store` | `StorePasswordError`, mensaje claro sin traceback | **OK** |
| 4 | **Almacén inexistente / corrupto** | Ruta inexistente o fichero alterado | `StoreCorruptedError`, aviso amigable al usuario | **OK** |
| 5 | **Alias duplicado** | Generar clave con alias ya existente | Rechazo con `AliasExistsError`, almacén intacto | **OK** |
| 6 | **Campos opcionales DName** | Solo CN rellenado, resto vacíos | Se genera el par de claves sin error | **OK** |
| 7 | **CN vacío por defecto** | Pulsar Enter en CN | Asigna 'Unknown' por defecto como en Java Keytool | **OK** |
| 8 | **Generación de CSR y validación RSA** | `--genkeypair` + `--certreq` | CSR PEM con clave pública RSA 2048 bits y firma SHA-256 | **OK** |
| 9 | **Contraseña incorrecta alias** | Contraseña de clave errónea en CSR | No se extrae la clave privada ni se crea el archivo `.csr` | **OK** |
| 10 | **Validación de caracteres en alias** | Separadores de ruta (`../bad`) | `ValueError`, prevención de ataques de path traversal | **OK** |
| 11 | **Compatibilidad flags `--genkeypair` y `--keystore`** | Parámetros estándar de Java keytool | Ejecución fluida sin diferencias de sintaxis | **OK** |
| 12 | **Listado de entradas (`--list`)** | Almacén con claves activas | Muestra tipo `PrivateKeyEntry`, DName y SHA-256 | **OK** |
| 13 | **Exportación de certificado (`--exportcert`)** | Exportar certificado a `.crt` | Fichero `.crt` X.509 PEM válido y legible | **OK** |
| 14 | **Inspección de certificado (`--printcert`)** | Archivo `.crt` exportado | Impresión de campos de sujeto, validez y huella digital | **OK** |
| 15 | **Eliminación y cancelación (`--delete`)** | Confirmar con 'n' y luego 's' | 'n' mantiene el alias intacto; 's' lo elimina del almacén | **OK** |
| 16 | **Restricción contraseñas Keytool** | 1-5 caracteres rechazados, 6+ espacios/Unicode | Exige mínimo 6 caracteres exactos y acepta espacios | **OK** |
| 17 | **Alias por defecto 'mykey' e insensibilidad** | Alias vacío o mayúsculas ('MYKEY') | Asigna 'mykey' y no distingue mayúsculas/minúsculas | **OK** |
| 18 | **Validez estándar de 90 días** | Generación de certificado autofirmado | Comprobación de validez de 90 días exactos | **OK** |
| 19 | **Normalización de código de país** | Introducir 'es' en minúsculas en DName | Normaliza automáticamente a mayúsculas 'ES' | **OK** |

---

## 6. Cobertura de la Rúbrica de Evaluación

| Criterio de Evaluación | Ponderación | Estado | Detalle de Implementación |
|---|:---:|:---:|---|
| **Funcionalidad CLI** | 20% (2.0 pts) | **100%** | Implementación de `--help`, `--genkeypair`/`--genkey`, `--certreq`, soporte de `--store`/`--keystore` y captura interactiva de argumentos. |
| **Criptografía y KeyStore** | 20% (2.0 pts) | **100%** | Generación RSA 2048 bits, CSR PEM con firma SHA-256, persistencia cifrada multicapa (PBKDF2 600k + Fernet + PKCS#8). |
| **GitHub y Documentación** | 10% (1.0 pts) | **100%** | Historial de commits equilibrado de ambos integrantes, README completo con fundamentación teórica, ejemplos de consola y matriz de pruebas. |
| **Defensa Presencial Individual** | 20% (2.0 pts) | **Preparada** | Guía de defensa detallada en `PROCESO_CREACION.txt` con respuestas a preguntas teóricas frecuentes. |
| **Ampliaciones** | 30% (3.0 pts) | **100%** | **4 comandos adicionales**: `--list`, `--exportcert`, `--printcert`, `--delete`, certificados X.509 autofirmados y compatibilidad de flags. |

