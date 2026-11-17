# pgprobe

A tiny Go CLI and library that answers one question: is PostgreSQL actually reachable from here? It needs no credentials and no database driver. It resolves the host, opens a TCP connection and sends the Postgres `SSLRequest` message. A real Postgres server replies with one byte, `S` or `N`, so pgprobe can tell apart DNS problems, refused connections, timeouts, a port held by something that is not Postgres, and a healthy server. Standard library only.

## Why

"Connection refused" from an app can mean five different things. Before touching passwords or `pg_hba.conf`, you want to know whether packets reach Postgres at all. `pg_isready` does this but needs the Postgres client packages; pgprobe is a single static binary you can drop into any container.

## Install

```
go install github.com/PrinceAdvant/pgprobe/cmd/pgprobe@latest
```

## Usage

```
pgprobe "postgres://app:secret@db:5432/app"
pgprobe db:5432
DATABASE_URL=postgres://... pgprobe -json
```

The password in a URL is never sent anywhere; only host and port are used.

Example output:

```
db:5432 stage=dns tls=false time=3ms
error: lookup db on 127.0.0.11:53: no such host
hint: host name does not resolve; inside Docker use the service name on a shared network, not localhost
```

```
db:5432 stage=ok tls=false time=2ms
hint: Postgres is answering without TLS; if your app requires sslmode=require it will fail
```

Exit code 0 when Postgres answers, 1 otherwise. Useful as a wait-for step in an entrypoint:

```
until pgprobe -timeout 2s "$DATABASE_URL" >/dev/null; do sleep 1; done
```

## Stages

- **dns**: the name does not resolve. Inside Docker, `localhost` is the container itself.
- **connect**: refused (nothing listening, wrong port, `listen_addresses`) or timed out (firewall).
- **protocol**: something answered but not like Postgres, for example an HTTP service on that port.
- **ok**: Postgres is there. Remaining failures are about credentials, `pg_hba.conf` or TLS settings.

A longer troubleshooting guide is [Postgres connection refused in Docker](https://peon.sh/blogs/postgres-connection-refused-docker). Built by a contributor to [Peon](https://peon.sh/), an open-source self-hosted deployment platform.

MIT licensed.
