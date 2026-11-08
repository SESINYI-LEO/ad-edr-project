"""Break-glass account recovery, run on the server by someone with access to the host and its database.

    python -m app.cli reset-password admin            # prints a temporary password; the user must change it at next sign-in
    python -m app.cli reset-password admin --password 'N3w-Passw0rd!'
    python -m app.cli reset-authenticator admin       # for a lost phone; the user enrols a new one after signing in

Every use is written to the audit trail."""
import argparse
import sys

from sqlalchemy import select

from app.database import SessionLocal, init_db
from app.models import SystemUser
from app.services import accounts, audit


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("reset-password", help="set a new password and force a change at next sign-in")
    rp.add_argument("username")
    rp.add_argument("--password", help="use this password instead of generating one (min 8 characters)")
    ra = sub.add_parser("reset-authenticator", help="remove the user's authenticator app")
    ra.add_argument("username")
    args = ap.parse_args(argv)

    init_db()
    db = SessionLocal()
    try:
        user = db.scalar(select(SystemUser).where(SystemUser.username == args.username))
        if not user:
            print(f"No such user: {args.username}", file=sys.stderr)
            return 1
        if args.cmd == "reset-password":
            pw = args.password or accounts.temp_password()
            if len(pw) < 8 or len(pw) > 128:
                print("Password must be 8-128 characters", file=sys.stderr)
                return 1
            accounts.set_password(user, pw, must_change=True)
            accounts.clear_failures(user)
            audit.log(db, None, "password_reset_cli", details=f"target={user.username}")
            db.commit()
            print(f"Password for '{user.username}' reset. Temporary password: {pw}\nThey must change it at next sign-in.")
        else:
            user.totp_secret_enc = user.totp_pending_enc = None
            user.totp_last_step = 0
            accounts.clear_failures(user)
            audit.log(db, None, "authenticator_reset_cli", details=f"target={user.username}")
            db.commit()
            print(f"Authenticator removed for '{user.username}'. They can enrol a new one under Account after signing in.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
