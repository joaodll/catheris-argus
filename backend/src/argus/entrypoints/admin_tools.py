"""Operator helpers: deployment facts for the environment, and the recovery of a password.

    hash-password          prompts for a password (twice) and prints the .env line for the first
                           admin, with its argon2id hash. The password itself is never printed.
    new-secret-key         prints a fresh credential-encryption keyring for .env.
    reset-password USER    a forgotten password (ADR-0041): prompts for a new one, which the
                           user must change at the next sign-in, and ends their sessions. Run it
                           where the database is reachable, in the api container:
                             docker compose exec api python -m argus.entrypoints.admin_tools \\
                               reset-password USER
                             kubectl -n argus exec -it deploy/argus-api -- \\
                               python -m argus.entrypoints.admin_tools reset-password USER

Values are single-quoted: Docker Compose does not interpolate the "$" in an argon2 hash then.
"""

import argparse
import getpass
import sys

from argus.auth import check_password, hash_password, reset_password
from argus.core.db import get_engine
from argus.core.secrets import new_key


def _ask(username: str) -> str | None:
    password = getpass.getpass("New password: ")
    try:
        check_password(password, username)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return None
    if getpass.getpass("Repeat it: ") != password:
        print("the passwords differ", file=sys.stderr)
        return None
    return password


def hash_password_line() -> int:
    password = _ask("admin")
    if password is None:
        return 2
    print(f"ARGUS_BOOTSTRAP_ADMIN_PASSWORD_HASH='{hash_password(password)}'")
    return 0


def new_secret_key() -> int:
    print(f"ARGUS_SECRET_KEYS='k1:{new_key()}'")
    print("ARGUS_SECRET_KEY_ID='k1'")
    return 0


def reset(username: str) -> int:
    password = _ask(username)
    if password is None:
        return 2
    try:
        with get_engine().begin() as conn:
            reset_password(conn, username=username, password=password)
    except (LookupError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"{username}: password set; they choose their own at the next sign-in")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["hash-password", "new-secret-key", "reset-password"])
    parser.add_argument("username", nargs="?", help="reset-password: whose password")
    args = parser.parse_args(argv)
    if args.command == "reset-password":
        if not args.username:
            parser.error("reset-password needs a username")
        return reset(args.username)
    return hash_password_line() if args.command == "hash-password" else new_secret_key()


if __name__ == "__main__":
    sys.exit(main())
