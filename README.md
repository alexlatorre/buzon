# Buzón Seguro (Personal DropBox)

Buzón Seguro es una plataforma de entrega de archivos y mensajes con arquitectura **Zero-Knowledge** (Conocimiento Cero). Está diseñado para permitir que cualquier persona te envíe información de manera ultra-segura sin que el servidor sea capaz de leer el contenido.

https://gallifrey.sytes.net/

---

## 🚀 Guía de Usuario

### 1. Registro e Inicio de Sesión
- Crea una cuenta eligiendo un **Nombre de Usuario** y una **Contraseña Maestra**.
- El **medidor de fuerza** te indica en tiempo real la seguridad de tu contraseña (de rojo/muy débil a verde/muy fuerte).
- **IMPORTANTE**: Tu contraseña maestra es la única llave para tus datos. Si la pierdes, nadie (ni el administrador del servidor) podrá recuperar tus archivos, ya que están cifrados con ella.

### 2. Recibir Archivos (Drop)
- Una vez dentro, verás tu **Enlace Público**. Puedes compartirlo para recibir archivos.
- También puedes generar **Enlaces de Un Solo Uso** en la barra lateral. Estos enlaces dejan de funcionar después del primer envío exitoso.
- Puedes desactivar tu enlace público en cualquier momento desde la configuración en el Dashboard.

### 3. Descarga y Lectura
- Los paquetes recibidos aparecen en tu bandeja de entrada.
- Al abrir un paquete, el sistema lo descifra en tu navegador.
- Puedes descargar archivos individualmente o todos a la vez. Los archivos recuperarán su nombre y extensión original automáticamente.

### 4. Página de Seguridad
- Desde la pantalla de login, accede a **"¿Cómo funciona? Conoce nuestra seguridad →"** para ver una explicación visual completa de la arquitectura criptográfica y el flujo de datos.

### 5. Compartir Ficheros de Forma Segura
- Desde el dashboard, pulsa **📤 Compartir Fichero** en el menú lateral.
- Selecciona un archivo, establece una **contraseña de desbloqueo**, y opcionalmente añade un mensaje.
- Configura la **expiración** (1h, 24h, 7 días, 30 días o sin caducidad) y el **límite de descargas**.
- El navegador cifra el fichero con **AES-256-GCM** y protege la clave con **PBKDF2** derivada de la contraseña.
- Se genera un enlace que puedes copiar y enviar al receptor.
- El receptor abre el enlace, introduce la contraseña, y el fichero se descifra y descarga **exclusivamente en su navegador**.
- El servidor nunca tiene acceso al contenido del fichero ni a la contraseña.

---

## 🛡️ Seguridad

### Arquitectura Zero-Knowledge
A diferencia de otros servicios, Buzón Seguro utiliza **Cifrado de Extremo a Extremo (E2EE)** real. El servidor actúa únicamente como un "almacenamiento ciego" de bits cifrados.

#### ¿Dónde ocurre la magia?
Todo el procesamiento criptográfico ocurre **exclusivamente en el Navegador del Usuario** utilizando la API `window.crypto` (Web Crypto API).

1.  **En el Registro/Login (Receptor)**:
    - La contraseña maestra se utiliza para derivar una clave mediante **PBKDF2** (600.000 iteraciones, SHA-256).
    - Tu clave privada RSA-4096 se genera y se cifra con esa clave derivada **antes** de salir de tu ordenador.
    - El servidor solo guarda tu clave pública y tu clave privada envuelta (cifrada).

2.  **En el Envío (Remitente)**:
    - El remitente descarga tu clave pública.
    - Genera una clave simétrica **AES-GCM-256** aleatoria de un solo uso.
    - Cifra los archivos y el mensaje con esa clave AES.
    - Cifra la clave AES con tu clave pública RSA (**RSA-OAEP**).
    - Envía los datos cifrados al servidor.

3.  **En la Recepción (Receptor)**:
    - Tu navegador descarga el bloque cifrado.
    - Tu clave privada (descifrada en RAM tras el login) descifra la clave AES.
    - La clave AES descifra el mensaje y los archivos.

**Resultado**: El servidor nunca posee las llaves para ver tus archivos. Incluso si el servidor fuera comprometido, el atacante solo encontraría datos binarios ininteligibles.

### Content Security Policy (CSP)
El servidor aplica cabeceras HTTP de seguridad estrictas:
- **`script-src 'self'`** — solo se ejecutan scripts del propio servidor, bloqueando cualquier inyección XSS.
- **`frame-ancestors 'none'`** — protección anti-clickjacking.
- **`Referrer-Policy: no-referrer`** — no filtra información de navegación.
- **`Cache-Control: no-store`** — no se cachean datos sensibles.
- **`Permissions-Policy`** — deshabilita cámara, micrófono y geolocalización.

### Verificación de Integridad de Ficheros
Para mitigar el riesgo de que un atacante modifique los ficheros servidos:

1. **Hashing en el servidor**: Al arrancar, el servidor calcula el **SHA-256** de todos los ficheros públicos críticos (`app.js`, `crypto.js`, `integrity.js`, `style.css`, etc.) y los expone en `/api/integrity`.
2. **Verificación independiente en el cliente**: El navegador descarga cada fichero, calcula su hash SHA-256 de forma independiente y lo compara con lo reportado por el servidor.
3. **Detección de cambios (localStorage)**: La primera vez que visitas, se guardan las huellas digitales. En visitas posteriores, cualquier cambio dispara una **alerta de integridad**.
4. **Verificación contra GitHub**: Los nombres de fichero en el panel de integridad son links directos al código fuente en [GitHub](https://github.com/alexlatorre/buzon/tree/master/public), permitiendo verificar manualmente que el código no ha sido manipulado.

> **Nota**: Un atacante que controle el servidor podría reescribir `integrity.js` para evadir esta verificación. Por eso se recomienda siempre comparar los hashes contra el repositorio público de GitHub como fuente de verdad externa.

### Otras Características de Seguridad
- **Boss Key** (doble ESC): Cierre instantáneo de sesión con limpieza de memoria.
- **Enlaces de Un Solo Uso**: Se invalidan automáticamente después de un envío.
- **Enlace Público desactivable**: Corta el acceso externo en cualquier momento.
- **Destrucción de paquetes**: Eliminación permanente de archivos del servidor tras su lectura.
- **Medidor de fuerza de contraseña**: Evalúa longitud, variedad de caracteres y unicidad en tiempo real.
- **Diseño responsive**: Interfaz adaptada para móviles y tablets con sidebar deslizante y layouts optimizados.

### 🔏 Hashes Confiables (SHA-256)
Usa esta tabla como fuente de verdad externa para verificar que los ficheros servidos por tu instancia no han sido manipulados. Compara estos hashes con los que muestra el panel de integridad de la aplicación.

| Fichero | SHA-256 |
|---|---|
| `app.js` | `a13d51ca0cfd2d28f356429ff3e5afdad9cc10c48125b253d9c169427f6c0bd4` |
| `crypto.js` | `27eca691dc43573d5a7eaaebcb5fed60aa40e23dc797647ef3c6df690850441c` |
| `integrity.js` | `b5d6bbfd4140cc7468c2947f43ea9bf188e28f28c9ca4b7021d4d3386973832d` |
| `share.js` | `a4a478b9387495911b4a74e292ec8a522cae1e9fdcfb00ae15fde5094f5ac26a` |
| `drop.js` | `fe68762008b9712982a0b8f0a77f5cbcc70878f611c19ea7d3e0793072ac8eb2` |
| `style.css` | `4b5e927ae82ad1e4ab5d2e3a20f96da1f24267ce9c694ca10f1eadba1a62dd8f` |
| `index.html` | `d9f69dd08dc6cabea335ce9a096c7252298d0c75bd27523ee88cd97d29bb9a44` |
| `about.html` | `ec956c4e8d367185f405db8a13854ae9290f050f9204ff64299eea72df5888f3` |
| `drop.html` | `212cfaadd493f015dff8d832cb01f30139dcecf7eff48adcd5233d4d29277888` |
| `share.html` | `5911ceedff70cfe6cac45c2c33683e36fbeeeec1d816646ee3eb65d0ba3956de` |

> **Verificación manual**: Abre la consola del navegador (F12) y ejecuta:
> ```javascript
> fetch('/app.js').then(r=>r.text()).then(t=>crypto.subtle.digest('SHA-256',new TextEncoder().encode(t))).then(h=>console.log(Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('')))
> ```

---

## 🐳 Docker

### Construir la imagen
```bash
docker build -t shadow-drop .
```

### Ejecutar con volumen de datos persistente
```bash
docker run -d -p 4000:4000 -v /ruta/datos:/app/data --name shadow-drop shadow-drop
```

### Con certificados SSL propios
```bash
docker run -d -p 4000:4000 \
  -v /ruta/datos:/app/data \
  -v /ruta/cert.pem:/app/cert.pem \
  -v /ruta/key.pem:/app/key.pem \
  --name shadow-drop shadow-drop
```

### Exportar / Importar imagen
```bash
docker save -o shadow-drop.tar shadow-drop   # Exportar
docker load -i shadow-drop.tar               # Importar
```

---

## ⚙️ Instalación y Configuración

### Requisitos
- **Node.js** (v18 o superior recomendado).
- **HTTPS**: Es obligatorio para que el navegador permita el uso de las APIs criptográficas. Se incluyen certificados de prueba (`cert.pem`, `key.pem`).

### Configuración de Base de Datos
El sistema soporta dos motores: **SQLite** (por defecto) y **MySQL**.
Puedes configurarlo en `config.js`:

```javascript
module.exports = {
    db: {
        engine: 'sqlite', // o 'mysql'
        mysql: {
            host: 'localhost',
            user: 'root',
            password: 'tu_password',
            database: 'buzon'
        }
    }
};
```

*Nota: Si usas MySQL, asegúrate de ejecutar `npm install mysql2`.*

### Ejecución
1. Instala dependencias: `npm install`.
2. Inicia el servidor: `npm start` o `node server.js`.
3. Accede a `https://localhost:4000`.

---

## 📂 Estructura del Proyecto
- `/public`: Frontend (Vanilla JS, HTML, CSS). Diseño premium inspirado en Apple.
  - `integrity.js`: Sistema de verificación de integridad de ficheros.
  - `crypto.js`: Utilidades criptográficas (PBKDF2, RSA-OAEP, AES-GCM).
  - `about.html`: Página de información de seguridad.
- `/db`: Drivers de base de datos (SQLite/MySQL).
- `/data`: Almacenamiento local (Base de datos y archivos cifrados).
- `server.js`: API Backend (Express) con CSP y cabeceras de seguridad.
- `config.js`: Configuración global.
- `Dockerfile`: Imagen Docker con Alpine y Node 20.
