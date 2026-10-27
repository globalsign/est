# estserver

Application estserver is a basic EST server for testing purposes.

`trust_proxy_headers` defaults to false, so the server uses the connection's
peer address. To retain forwarded client addresses, set it to true only when
every request passes through a trusted reverse proxy that removes or
overwrites both `X-Real-IP` and `X-Forwarded-For`. The server does not check the
proxy's source address. When enabled, `X-Real-IP` takes precedence.
