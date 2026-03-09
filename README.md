# Buzón Seguro (Personal DropBox)

Buzón Seguro es una plataforma de entrega de archivos y mensajes con arquitectura **Zero-Knowledge** (Conocimiento Cero). Está diseñado para permitir que cualquier persona te envíe información de manera ultra-segura sin que el servidor sea capaz de leer el contenido.

https://gallifrey.sytes.net/

---

## 🚀 Guía de Usuario

### 1. Registro e Inicio de Sesión
- Crea una cuenta eligiendo un **Nombre de Usuario** y una **Contraseña Maestra**.
- **IMPORTANTE**: Tu contraseña maestra es la única llave para tus datos. Si la pierdes, nadie (ni el administrador del servidor) podrá recuperar tus archivos, ya que están cifrados con ella.

### 2. Recibir Archivos (Drop)
- Una vez dentro, verás tu **Enlace Público**. Puedes compartirlo para recibir archivos.
- También puedes generar **Enlaces de Un Solo Uso** en la barra lateral. Estos enlaces dejan de funcionar después del primer envío exitoso.
- Puedes desactivar tu enlace público en cualquier momento desde la configuración en el Dashboard.

### 3. Descarga y Lectura
- Los paquetes recibidos aparecen en tu bandeja de entrada.
- Al abrir un paquete, el sistema lo descifra en tu navegador.
- Puedes descargar archivos individualmente o todos a la vez. Los archivos recuperarán su nombre y extensión original automáticamente.

---

## 🛠️ Detalles Técnicos y Seguridad

### ¿Por qué es seguro? (Arquitectura Zero-Knowledge)
A diferencia de otros servicios, Buzón Seguro utiliza **Cifrado de Extremo a Extremo (E2EE)** real. El servidor actúa únicamente como un "almacenamiento ciego" de bits cifrados.

#### ¿Dónde ocurre la magia?
Todo el procesamiento criptográfico ocurre **exclusivamente en el Navegador del Usuario** utilizando la API `window.crypto` (Web Crypto API).

1.  **En el Registro/Login (Receptor)**:
    - La contraseña maestra se utiliza para derivar una clave mediante **PBKDF2**.
    - Tu clave privada RSA se genera y se cifra con esa clave derivada **antes** de salir de tu ordenador.
    - El servidor solo guarda tu clave pública y tu clave privada envuelta (cifrada).

2.  **En el Envío (Remitente)**:
    - El remitente descarga tu clave pública.
    - Genera una clave simétrica **AES-GCM** aleatoria de un solo uso.
    - Cifra los archivos y el mensaje con esa clave AES.
    - Cifra la clave AES con tu clave pública RSA (RSA-OAEP).
    - Envía los datos cifrados al servidor.

3.  **En la Recepción (Receptor)**:
    - Tu navegador descarga el bloque cifrado.
    - Tu clave privada (descifrada en RAM tras el login) descifra la clave AES.
    - La clave AES descifra el mensaje y los archivos.

**Resultado**: El servidor nunca posee las llaves para ver tus archivos. Incluso si el servidor fuera comprometido, el atacante solo encontraría datos binarios ininteligibles.

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
- `/db`: Drivers de base de datos (SQLite/MySQL).
- `/data`: Almacenamiento local (Base de datos y archivos cifrados).
- `server.js`: API Backend (Express).
- `config.js`: Configuración global.
