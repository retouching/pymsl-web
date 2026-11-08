# pymsl-web

pymsl-web is a Python library, imported as `pymsl_web`, that implements the client side of Netflix's Message Security
Layer (MSL) for the web player: the handshake (`NONE` entity authentication, `ASYMMETRIC_WRAPPED` key exchange), the
requests (`NETFLIXID` user authentication, then the user ID token) and a session the application exports and
restores. The reference is the JavaScript implementation of [Netflix/msl](https://github.com/Netflix/msl).

This file holds every rule of the project. There is no other rule page.

## Rules of the layout

1. **One subject per file.** A file holds one public class, with the constants that this class alone uses. Enums
   are never nested in a class: the enums of the package live in `enums.py`, its errors in `exceptions.py`. Several
   public classes share a file only when they are all data models (pydantic models). If the subject of a file
   cannot be named in one noun, split the file.
2. **One subject per folder.** A folder is named after one subject. When it holds files of several sub-subjects,
   each sub-subject is a sub-package (`keyexchange/asymmetric_wrapped/`, `entityauth/schemes/`). If the subject of
   a folder cannot be named in one noun, split it. A subject of one file is a module, a subject of several files is a
   package: `compression/gzip.py` is one file, `compression/lzw/` holds the compression, its reader and its writer.
3. **An object does its own work.** The data of an object and the operations that concern that object alone are
   methods of its class: a master token reads its fields and tells whether it expired
   (`MasterToken.parse()`, `MasterToken.is_expired()`).
4. **A collection does the work of the collection.** `ServiceTokens` holds the service tokens of a session and
   stores, replaces and forgets them. It does not write a message.
5. **Work that coordinates several objects gets its own class**, in its own file, beside the objects it
   coordinates: `MessageWriter` and `MessageReader` (`messages/`) write and read a message, `MSLClient` chains a
   handshake or a request.
6. **Variable rules are composed, not inherited.** When a behaviour changes from one case to the next, each case is
   a class behind a small interface, in a file of its own: the entity authentication schemes
   (`EntityAuthentication`), the user authentication schemes (`UserAuthentication`), the key exchange schemes
   (`KeyExchange`), the compressions (`Compression`). A new scheme is a new class; the core never changes for it.
7. **Code lives with its users.** Code that one package uses lives in that package, in a sub-package when it is a
   subject of its own. Code that several packages use lives in their closest common parent. Code that knows
   nothing of MSL (Base64, JSON, a message text) lives in `utils/`.
8. **`utils/` is generic.** It holds what knows nothing of MSL. A helper that knows an MSL concept lives with that
   concept. A utility that grows is split into a package.
9. **The direction of the imports.** The packages form layers, from the top: `client`; `transport` and `session`;
   the schemes (`entityauth`, `userauth`, `keyexchange`) and `messages`; `tokens`; `crypto` and `compression`;
   `utils`. A package imports only the layers below it. `enums` and `exceptions` import nothing of pymsl-web but
   `utils`; `configuration` imports the schemes and `enums`. import-linter checks this rule.
10. **Everything is a class.** Functions are the methods of a class. Module functions exist only in `utils/`.
11. **The configuration is strict pydantic models.** `MSLConfiguration` and the model of each scheme are
    `frozen=True, extra="forbid", strict=True`. There is no configuration file: the application builds them in code.
    A rule of a value is a validator of its model.
12. **pymsl-web decides nothing for the application.** It never starts a handshake, renews a session or retries a
    request on its own, never waits between two requests, and never reads nor writes a file, a database or any
    storage: the session becomes data with `export()` and comes back with `restore()`.

## Rules of the code

Every file meets these rules. They hold in the tests too.

- Every model is a pydantic model; no dataclass.
- ruff bans the `dataclasses` module (TID251): a `dataclasses.replace` on a pydantic model passes mypy and fails at
  run time. ruff bans starting a process too: pymsl-web starts none.
- Every method and function has a docstring, in the imperative, saying what it does ("Keep the newest token.").
  Nothing else has one: no class, module or constant docstring.
- No `#` comment, except `# noqa` and `# type: ignore` with their code.
- No name starts with `_`: no private function, method, attribute or constant. Python's own dunders
  (`__init__`, `__all__`) are the only exception.
- Type everything; mypy runs in strict mode.
- An acronym in a class name is upper case (`MSLClient`, `JWK`, `HTTPTransport`, `LZWCompression`).
- An error message follows `message(subject, outcome, *causes)` (`utils/messages.py`): `Answer: invalid (header)`.
  A message never holds a key, a cookie or a token.
- Everything is in English: code, docs, messages, commits.

## The parts

- `client.py`: `MSLClient`, the handshake and the requests.
- `configuration.py`: `MSLConfiguration`, the URL, the schemes, the compression, the languages, the checks.
- `session/`: `MSLSession`, its exported state `MSLSessionState`, its `Clock` in server time.
- `messages/`: the header data, the error data, the payload chunks, the capabilities, `MessageWriter` and
  `MessageReader`.
- `tokens/`: `MasterToken`, `UserIDToken`, `ServiceToken`, `ServiceTokens`, kept as received.
- `crypto/`: the ciphertext envelope, the null, session and server crypto contexts, the JWK.
- `entityauth/`, `userauth/`, `keyexchange/`: one interface each and its schemes (`NONE`, `NETFLIXID`,
  `ASYMMETRIC_WRAPPED`).
- `compression/`: GZIP and the LZW of MSL.
- `transport/`: the HTTP transport over curl_cffi.
- `utils/`: Base64, JSON, the messages.

## Tests

- Two levels: the unit tests (`tests/unit/`) and the e2e tests (`tests/e2e/`). pymsl-web talks to no database: there
  is no integration level.
- The unit tests run after each iteration of code; the e2e tests run once at the end of all the iterations of a
  piece of work. Each time, run the tests of what changed alone; the pre-push hook alone runs the whole unit suite.
- A file of `pymsl_web/` comes with its unit tests in the commit that adds or moves it.
- `tests/unit/` follows the tree of `pymsl_web/`: the tests of `pymsl_web/compression/lzw/lzw.py` live in
  `tests/unit/compression/lzw/test_lzw.py`.
- Each piece of work adds the e2e tests of what it changes.
- No test holds a token, a cookie or a key captured from Netflix: every one is made up by the test.
- A test run removes everything it creates, even after a failure: its containers, networks, volumes and images,
  and its temporary files (`tmp_path_retention_policy = "none"`).
- The owner checks pymsl-web by hand against the real web service. The owner's working code,
  `~/Téléchargements/MSL/` (outside the repository), is the reference of the real wire format.

### Unit tests

- A test is a method of a class `Test<Subject>`, with a docstring in the imperative. The rules of the code hold:
  no `#` comment, no class docstring.
- A test checks one behaviour of what the code does now, and its limits: an edge value, an invalid input, a
  failure. It never checks a document nor a behaviour the code no longer has.
- Inject, don't patch: the code receives a fake HTTP poster, a clock with a fixed source. The shared fakes and
  factories live in `tests/unit/support/`.
- The guard of `tests/unit/conftest.py` blocks TCP and UDP (pytest-socket) and moves the current directory and
  `HOME` into `tmp_path` for every test.
- pytest-randomly shuffles the order of the tests on every run. Hypothesis tests the parsers (tokens, headers,
  envelopes, LZW) with invariants.
- A unit test never uses the network, Docker nor a real platform.

### E2E tests

- A test is a method of a class `Test<Feature>` marked `e2e`. It uses the public API of pymsl-web
  (`from pymsl_web import ...`) and nothing else of it.
- It talks to a fake MSL server that lives in `tests/e2e/server/` alone, runs in the stack and never imports
  `pymsl_web` (import-linter checks it).
- Each run gets its own stack `pymsl-web-e2e-<hex>` (`docker/compose.e2e.yaml`, `tests/e2e/stack.py`), removed with
  its volumes and images at the end even after a failure; then a listing of every Docker object with its label
  fails the run for a leftover. A Docker command is always scoped by that project name or label.

## Documents

- This file is the one source of the rules.
- `README.md` stays short: what pymsl-web is, how to install it, one example. `docs/` holds one page per subject.
- `ROADMAP.md`, in French, holds what is agreed but not built. It stays local: never committed.
- The specs and plans of the superpowers skills never go in the repository.

## Git

- Conventional Commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `build:`, `chore:`), small and focused,
  in English; `!` after the type for a breaking change, without a `BREAKING CHANGE:` footer. No `Co-Authored-By`
  line.
- The work happens on `master`; no development branch.
- No push unless the owner asks.

## Working with the owner

- Build only what the owner asks. A choice that belongs to the owner is asked as one question, with options and a
  recommendation.
- Subagents work only when the owner asks for them explicitly. Without that, the main session does the work
  itself.
- The work goes in iterations; each one ends with the unit tests of what it built, then a commit. The e2e tests
  of the work run once, after the last iteration.

## Hooks

- commit-msg: the Conventional Commits check.
- pre-commit: `ruff check --fix`, `ruff format`, mypy, import-linter, and the end-of-file and trailing-whitespace
  fixers.
- pre-push: `ruff check`, `ruff format --check`, mypy and import-linter on the whole repository, then the whole unit
  suite, without Docker. Zero test collected (exit code 5 of pytest) does not fail the push.

## Commands

- Set up: `uv sync`, then `uv run pre-commit install`.
- Lint and format: `uv run ruff check --fix .`, `uv run ruff format .`.
- Types: `uv run mypy`.
- Imports: `uv run lint-imports`.
- Unit tests: `uv run pytest <the test files of what changed>`; the whole suite, `uv run pytest`, is the
  pre-push hook's.
- E2E tests (Docker): `uv run pytest tests/e2e/<...>`.
- Every hook on every file: `uv run pre-commit run --all-files`, and
  `uv run pre-commit run --hook-stage pre-push --all-files` for the pre-push hook.
- Dependencies: `uv add <pkg>`, `uv add --dev <pkg>`; never `pip install`. Commit `uv.lock` with the change.
