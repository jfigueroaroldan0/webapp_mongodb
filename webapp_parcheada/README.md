# DocVault — versión SEGURA (parcheada)

Explorador web de MongoDB (Flask) que se conecta al servidor con las **cuentas
reales de Mongo**, muestra las bases de datos y colecciones **accesibles según
los permisos** de cada usuario y permite ver documentos y hacer CRUD.

Esta es la **versión segura**: idéntica a `docvault_vulnerable` salvo en la
función `read_documents()`, que ya **no es inyectable**.

## Arranque

```bash
pip install -r requirements.txt
python app.py        # http://127.0.0.1:5001
```

Entra con una cuenta real de tu servidor Mongo. Configurable por variables de
entorno: `MONGO_HOST`, `MONGO_PORT`, `AUTH_SOURCE`, `SECRET_KEY`.

## El parche

La entrada del usuario **nunca** entra en la consulta como código. Se recuperan
los documentos con una consulta fija y, si hay búsqueda, se filtra en la
aplicación tratando el texto como dato literal:

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

Alternativa segura para filtrar en el servidor: `{"campo": {"$regex": re.escape(q),
"$options": "i"}}` — nunca concatenación en `$where`.

## Demostración de que el ataque ya no funciona

Con esta versión en marcha, introduce en el buscador el mismo payload que
funcionaba en la versión vulnerable:

```
x') >= 0 || true || ('
```

Ahora se trata como una cadena literal: no hay ningún documento que la contenga y
la búsqueda **no devuelve nada**. Inyección neutralizada.
