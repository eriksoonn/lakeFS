# FastAPI ACL Authentication Server

This directory contains a simple reference implementation of the lakeFS ACL authentication server written in [FastAPI](https://fastapi.tiangolo.com/).

## Building

```
docker build -t lakefs-fastapi-auth .
```

## Running

```
docker run -p 8000:8000 lakefs-fastapi-auth
```

Once running, you can check the server health using:

```bash
curl http://localhost:8000/api/v1/health
```

which returns `{"status": "ok"}` on success.

All API routes are served under the `/api/v1` prefix.  For example, to list
users call `http://localhost:8000/api/v1/auth/users`.

The server supports two storage modes controlled by the `FASTAPI_AUTH_STORAGE`
environment variable:

* `memory` - (default) keep all data in memory.
* `postgres` - store all data in PostgreSQL specified by `DATABASE_URL`.

You can run the server together with PostgreSQL using `docker compose`:

```bash
docker compose up
```

The compose file sets the storage mode and database connection string using
environment variables, allowing override in the same style as
`LAKEFS_AUTH_API_ENDPOINT`.

## Testing

Run unit tests using `pytest`:

```bash
pytest tests
```
