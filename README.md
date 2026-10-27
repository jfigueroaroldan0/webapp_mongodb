# DocVault — Explorador web de MongoDB (versión vulnerable y versión segura)

Aplicación web en **Flask** que actúa como **cliente remoto de MongoDB**: se
conecta al servidor con las **cuentas reales de Mongo**, muestra las bases de
datos y colecciones **accesibles según los permisos** de cada usuario y permite
ver documentos y hacer CRUD (insertar, editar, borrar).

El repositorio contiene **dos versiones** de la misma aplicación, para demostrar
una vulnerabilidad de **NoSQL Injection** y su corrección:

| Ubicación             | Versión    | Buscador de documentos                         | Puerto |
|-----------------------|------------|------------------------------------------------|--------|
| raíz del repositorio  | Vulnerable | Inyectable vía `$where` (JavaScript)           | 5000   |
| `webapp_parcheada/`   | Segura     | Parcheado (la entrada nunca entra en la query) | 5001   |

Ambas versiones son **idénticas** salvo en la función `read_documents()` de
`app.py`. Así se ve con claridad el "antes" y el "después" del parche.

> ⚠️ La versión vulnerable es solo para practicar en un entorno local y
> controlado. No la expongas en una red accesible ni en producción.

---

## Estructura del repositorio

```
.                             # versión VULNERABLE (raíz)
├── README.md                 # este fichero
├── app.py                    # buscador con $where (vulnerable)
├── requirements.txt
├── static/style.css
├── templates/                # base.html, login.html, dashboard.html
└── webapp_parcheada/         # versión SEGURA (parcheada)
    ├── app.py                # buscador parcheado
    ├── README.md
    ├── requirements.txt
    ├── static/style.css
    └── templates/
```

---

## Requisitos

- Python 3.9 o superior.
- Un servidor MongoDB accesible por red, con autenticación activada
  (`security.authorization: enabled`) y cuentas creadas con `db.createUser(...)`.
- El servidor debe escuchar en una IP accesible desde el cliente (ajusta
  `bindIp` en `/etc/mongod.conf`) y tener abierto el puerto 27017.

Para que se note el "acceso según permisos", conviene tener al menos dos cuentas
de Mongo con privilegios distintos. Ejemplo:

```javascript
use admin
db.createUser({ user: "jesusfigueroa", pwd: "usuario", roles: [ "root" ] })
db.createUser({ user: "lector", pwd: "lector123",
                roles: [ { role: "read", db: "futbol" } ] })
```

Con `jesusfigueroa` se ven todas las bases; con `lector`, solo la base `futbol`
en modo lectura (no puede insertar ni borrar: lo impide Mongo).

---

## Instalación y arranque

Cada versión se ejecuta por separado:

```bash
# Versión vulnerable (en la raíz del repositorio)
pip install -r requirements.txt
python app.py                 # http://127.0.0.1:5000

# Versión segura (en otra terminal; usa el puerto 5001)
cd webapp_parcheada
pip install -r requirements.txt
python app.py                 # http://127.0.0.1:5001
```

Como usan puertos distintos (5000 y 5001), puedes tener las dos abiertas a la vez
y compararlas. Entra con una cuenta real de tu servidor Mongo.

La conexión se puede configurar sin tocar el código, mediante variables de
entorno: `MONGO_HOST`, `MONGO_PORT`, `AUTH_SOURCE`, `SECRET_KEY`. Ejemplo:

```bash
MONGO_HOST=192.168.122.36 AUTH_SOURCE=admin python app.py
```

---

## Cómo funciona la aplicación

1. **Login contra Mongo.** El usuario y la contraseña del formulario son los de
   una cuenta real del servidor MongoDB; la app los usa para conectarse mediante
   el protocolo SCRAM. Si Mongo acepta, la sesión queda abierta con esa cuenta.
2. **Exploración por niveles**, con la conexión del propio usuario:
   bases de datos → colecciones → documentos (mostrados en JSON).
3. **Permisos = los de Mongo.** Todas las operaciones se ejecutan con la conexión
   del usuario, así que se ve y se puede modificar solo lo que sus permisos
   permiten. Una cuenta de solo lectura no podrá insertar/editar/borrar.

La cadena de conexión que monta la aplicación tiene esta forma:

```
mongodb://<usuario>:<contraseña>@<host>:27017/?authSource=admin
```

---

## La vulnerabilidad (versión de la raíz)

El buscador construye un `$where` concatenando el texto introducido, que Mongo
ejecuta como JavaScript (`read_documents()`):

```python
where = "JSON.stringify(this).indexOf('%s') >= 0" % q
col.find({"$where": where})
```

### Demostración

En el buscador de una colección, introduce:

```
x') >= 0 || true || ('
```

La condición que se genera y ejecuta Mongo queda:

```javascript
JSON.stringify(this).indexOf('x') >= 0 || true || ('') >= 0
```

El `|| true` la hace **siempre verdadera**, de modo que la búsqueda devuelve
**todos los documentos**, ignorando el término buscado. El atacante controla la
lógica de la consulta. Además, `$where` ejecuta JavaScript en el servidor, lo
que abre la puerta a extracción de datos a ciegas y a denegación de servicio.

> `$where` requiere que el servidor Mongo tenga habilitada la ejecución de
> JavaScript (`security.javascriptEnabled`, activada por defecto).

---

## El parche (carpeta `webapp_parcheada`)

La entrada del usuario **nunca** entra en la consulta como código. Los documentos
se recuperan con una consulta fija y, si hay búsqueda, se filtra en la aplicación
tratando el texto como un dato literal:

```python
docs = list(col.find({}).limit(LIMIT))   # consulta fija, sin entrada del usuario
if q:
    needle = str(q).lower()
    docs = [d for d in docs if needle in json_util.dumps(d).lower()]
```

Medidas aplicadas:

1. Se elimina por completo `$where` (ya no se ejecuta JavaScript).
2. La entrada se usa solo como **valor**, nunca como código.
3. Se fuerza el tipo con `str()`, lo que neutraliza la inyección de operadores
   como `{"$ne": null}`.

Alternativa segura para filtrar en el servidor:
`{"campo": {"$regex": re.escape(q), "$options": "i"}}` — nunca concatenación en
`$where`.

### Demostración de que el ataque ya no funciona

Con la versión segura en marcha, introduce en el buscador el mismo payload:

```
x') >= 0 || true || ('
```

Ahora se trata como una cadena literal: no hay ningún documento que la contenga y
la búsqueda **no devuelve nada**. Inyección neutralizada.
