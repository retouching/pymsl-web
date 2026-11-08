# Usage

pymsl has one entry point, `MSLClient`. It runs a handshake, sends requests and keeps an `MSLSession` that the
application reads, exports and restores. pymsl never handshakes, retries or stores anything on its own: the
application decides.

## Configuration

`MSLConfiguration` is a strict model: an unknown field or a value of the wrong type is refused when it is built.

| Field | Holds | Default |
| --- | --- | --- |
| `url` | the endpoint of the handshake and of the requests, when a call names none | required |
| `entity_authentication` | the entity scheme and the sender: `NoneEntityAuthentication(identity=<ESN>)` | required |
| `key_exchange` | the key exchange scheme: `AsymmetricWrappedKeyExchange(keypair_id="superKeyPair")` | required |
| `user_authentication` | the user scheme: `NetflixIDUserAuthentication(netflix_id=..., secure_netflix_id=...)` | none |
| `languages` | the `languages` of the capabilities | `()` |
| `compression` | the compression of the data sent: `GZIP`, `LZW` or `None` | `GZIP` |
| `compression_algorithms` | the `compressionalgos` of the capabilities | `(GZIP,)` |
| `encoder_formats` | the `encoderformats` of the capabilities | `("JSON",)` |
| `renewable` | the `renewable` flag of every header | `True` |
| `verify_signatures` | check the HMAC of the answers signed with the session keys | `True` |
| `server_public_keys` | the RSA public keys of the server, each PEM or Base64 SPKI DER; the handshake answer and the errors are accepted when one of them verifies their signature | `()`: not checked |

An answer is read in GZIP or LZW whatever the capabilities announce.

## Handshake

```python
client = MSLClient(configuration)
client.handshake(url="https://example.com/msl", params={"reqName": "manifest"})
```

The handshake sends the sender in clear with a fresh RSA public key and gets a master token and the session keys.
It sends no user authentication: the header is not encrypted. A handshake on a session that already has a master
token replaces it and forgets the user ID token and the service tokens of the old one. `http=` gives a
`curl_cffi.requests.Session` (or any object with the same `post`) to use instead of the one pymsl builds.

## Requests

```python
answer: bytes = client.request(data, url="https://example.com/msl/licence", params={"reqName": "license"})
```

A request sends `data` encrypted and signed with the session keys, compressed as configured, with the service
tokens the server gave and the user: the `userauthdata` of `user_authentication` until the server gives a user ID
token, then that token alone. It gives back the joined data of the answer. Reading the JSON of the service, and its
own `"error"` key, is the application's work. The message ID moves on by one after each request the server
answered, even when the answer is an error; it stays when the server could not be reached.

## Session

| Member | Gives |
| --- | --- |
| `client.session.active` | whether the session has a master token and its keys |
| `client.session.expired` | whether the master token expired, in server time (`True` without one) |
| `client.session.renewable` | whether the master token entered its renewal window, in server time |
| `client.session.export()` | an `MSLSessionState`, whose `model_dump_json()` is text |
| `MSLSession.restore(state)`, `MSLSession.restore_json(text)` | the session again, for `MSLClient(configuration, session=...)` |

The state holds the session keys in clear. The application keeps it where it wants and protects it as a secret.

```python
text = client.session.export().model_dump_json()
client = MSLClient(configuration, session=MSLSession.restore_json(text))
if client.session.expired:
    client.handshake()
```

## Errors

Every error of pymsl derives from `PyMSLError`.

| Error | When |
| --- | --- |
| `MSLError` | the server answered with an error header; `code` is an `MSLResponseCode` |
| `MSLTransportError` | the server could not be reached, or answered with an HTTP status outside 200–299 |
| `MSLMessageError` | the answer is malformed, its message ID or sequence is wrong, or a signature does not match |
| `MSLCryptoError` | a key or a ciphertext cannot be used |
| `MSLSessionError` | a request without a session, or a state that cannot be restored |

After an `MSLError`, pymsl forgets what the server refused, so the next call starts right:

| Code | pymsl forgets |
| --- | --- |
| `ENTITY_REAUTH`, `ENTITYDATA_REAUTH` | the master token, the keys, the user ID token and the service tokens bound to them |
| `USER_REAUTH`, `USERDATA_REAUTH`, `SSOTOKEN_REJECTED` | the user ID token and the service tokens bound to it |
| the others | nothing |

A failed answer that is not an `MSLError` changes nothing in the session.
