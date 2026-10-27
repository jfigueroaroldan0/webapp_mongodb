# DocVault — versión VULNERABLE

Explorador web de MongoDB (Flask) que se conecta al servidor con las **cuentas
reales de Mongo**, muestra las bases de datos y colecciones **accesibles según
los permisos** de cada usuario y permite ver documentos y hacer CRUD.

Esta es la **versión vulnerable**: el buscador de documentos es inyectable por
**NoSQL Injection** (`$where`). La versión corregida está en el proyecto hermano
`docvault_seguro`.

> ⚠️ Solo para practicar en local. No la expongas en red.

## Arranque

```bash
pip install -r requirements.txt
python app.py        # http://127.0.0.1:5000
```

Entra con una cuenta real de tu servidor Mongo. Configurable por variables de
entorno: `MONGO_HOST`, `MONGO_PORT`, `AUTH_SOURCE`, `SECRET_KEY`.

## La vulnerabilidad

El buscador monta un `$where` concatenando tu texto (JavaScript que Mongo
ejecuta), en `read_documents()`:

```python
where = "JSON.stringify(this).indexOf('%s') >= 0" % q
col.find({"$where": where})
```

Payload en el buscador:

```
x') >= 0 || true || ('
```

La condición generada queda `... || true || ...`, siempre verdadera, así que
devuelve **todos** los documentos ignorando la búsqueda. Para ver que ya no
funciona tras corregirlo, usa el proyecto `docvault_seguro`.

> `$where` requiere que Mongo tenga habilitada la ejecución de JavaScript
> (`security.javascriptEnabled`, por defecto activa).
