"""Start CertChain, or create the first admin account for a production install.

    python app.py                          start the server
    python app.py create-admin <username>  create an admin (prompts for a password)
"""
import getpass
import os
import sys

from waitress import serve

from certchain import create_app, create_site
from certchain.app_support import ApiError, check_password

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def create_admin(username: str) -> None:
    from certchain.anchors import SYSTEMS

    password = getpass.getpass("Password: ")
    try:
        check_password(password)
    except ApiError as err:
        sys.exit(err.message)
    for system in SYSTEMS:
        app = create_app(seed_demo=False, system=system)
        app.config["add_user"](username.strip().lower(), password, "admin", None, must_change=False)
    print(f"Admin '{username}' created on {', '.join(SYSTEMS)}.")


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "create-admin":
        return create_admin(sys.argv[2])
    if len(sys.argv) != 1:
        sys.exit(__doc__)

    env = os.environ.get("APP_ENV", "development")
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    if env == "development" and host not in LOOPBACK:
        sys.exit("Refusing to start: development mode has quick login, so it can only bind to localhost.")
    app = create_site(env=env)
    print(f"CertChain running at http://{host}:{port} ({env} mode)", flush=True)
    serve(app, host=host, port=port, threads=8)


if __name__ == "__main__":
    main()
