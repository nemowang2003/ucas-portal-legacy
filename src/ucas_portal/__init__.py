from .client import UCASPortalClient

__all__ = [
    "UCASPortalClient",
]


def main() -> None:
    import argparse
    import os

    username_from_env = os.getenv("UCAS_USERNAME")
    parser = argparse.ArgumentParser(
        description="A CLI for UCAS portal login.",
        suggest_on_error=True,
    )
    parser.add_argument(
        "--username",
        required=username_from_env is None,
        type=os.fsencode,
        help="Your UCAS username [env: UCAS_USERNAME]",
        default=username_from_env,
    )
    password_from_env = os.getenv("UCAS_PASSWORD")
    parser.add_argument(
        "--password",
        type=os.fsencode,
        required=password_from_env is None,
        help="Your UCAS password [env: UCAS_PASSWORD]",
        default=password_from_env,
    )
    args = parser.parse_args()

    client = UCASPortalClient(args.username, args.password)
    client.login()
