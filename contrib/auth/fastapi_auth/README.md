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

The server exposes the same basic endpoints as the Go example implementation found under `contrib/auth/acl`.

## Testing

Run unit tests using `pytest`:

```bash
pytest tests
```
