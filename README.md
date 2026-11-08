<h1 align="center">pymsl-web</h1>

<p align="center">
  The client side of Netflix's Message Security Layer (MSL), for the web player, in Python.
</p>

<p align="center">
  <img alt="Python 3.14" src="https://img.shields.io/badge/python-3.14-blue.svg">
  <img alt="uv" src="https://img.shields.io/badge/managed%20with-uv-DE5FE9.svg">
</p>

pymsl-web, imported as `pymsl_web`, speaks MSL the way Netflix's web player does: a `NONE` entity authentication with
the ESN as sender, an `ASYMMETRIC_WRAPPED` key exchange, and a user authenticated by the `NetflixId` and
`SecureNetflixId` cookies of the browser (`NETFLIXID`) until the server gives a user ID token. It handshakes, sends
requests and gives back their answers; the application decides when to handshake again and where to keep the
session.

## Install

pymsl-web needs Python 3.14 and [uv](https://docs.astral.sh/uv/).

From the project of the application, with a checkout of pymsl-web beside it:

```bash
uv add ../pymsl-web
```

## Example

```python
from curl_cffi import requests

from pymsl_web import (
    AsymmetricWrappedKeyExchange,
    MSLClient,
    MSLConfiguration,
    MSLSession,
    NetflixIDUserAuthentication,
    NoneEntityAuthentication,
)

configuration = MSLConfiguration(
    url="https://example.com/msl",
    entity_authentication=NoneEntityAuthentication(identity="NFCDCH-02-..."),
    key_exchange=AsymmetricWrappedKeyExchange(),
    user_authentication=NetflixIDUserAuthentication(netflix_id="...", secure_netflix_id="..."),
    server_public_keys=("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...",),
)
http = requests.Session(impersonate="chrome")

with MSLClient(configuration, http=http) as client:
    client.handshake()
    answer = client.request(b'{"version":2}')
    state = client.session.export().model_dump_json()

with MSLClient(configuration, http=http, session=MSLSession.restore_json(state)) as client:
    if client.session.expired:
        client.handshake()
    answer = client.request(b'{"version":2}')
```

`server_public_keys` takes the RSA public keys of the server, PEM or Base64 DER: the handshake answer and the errors
are then accepted only when one of them verifies their signature. The application gives its own curl_cffi session,
with its proxy and headers, or lets pymsl-web build one. The exported state holds the session keys in clear: keep it
as a secret.

## Documentation

- [Usage](docs/usage.md): the configuration, the handshake, the requests, the session and the errors.
