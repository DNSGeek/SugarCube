#!/opt/homebrew/bin/python3 -O

import argparse
import logging
from os import path

import requests

headers: dict[str, str] = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "curl/8.7.1",
}

PORT: int = 5123
ip: str = ""


def get_auth_cookie() -> str:
    global headers
    try:
        resp = requests.post(
            f"http://{ip}:{PORT}/api/v1/pair",
            params={"code": "auto"},
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        scauth = resp.json()["scauth"]
        resp.close()
        logging.debug(f"Got auth: {scauth}")
        headers["Cookie"] = (
            f"scauth={scauth}; Expires=Mon, 01-Jun-2037 00:00:00 GMT; Path=/"
        )
        return scauth
    except Exception as aex:
        logging.error(f"Unable to pull SugarCube auth: {aex}")
        logging.debug(f"Sent headers: {resp.request.headers}")
        logging.debug(f"Received headers: {resp.headers}")
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="This program will control a SugarCube", prog="sugarcube.py"
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="Enable debug mode [Default=False]",
        required=False,
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "-r",
        "--remote",
        help="The IP of the SugarCube to connect to",
        required=True,
    )
    parser.add_argument(
        "-p",
        "--port",
        help="The port to talk to on the remote SugarCube [Default=5123]",
        required=False,
        default=5123,
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s:\t%(message)s",
        level=logging.DEBUG if args.debug else logging.INFO,
    )

    ip = args.remote
    PORT = args.port
    authfile: str = f"/var/tmp/sc-{ip}.cookie"
    auth: str = ""
    if path.exists(authfile) and path.isfile(authfile):
        try:
            with open(authfile, "rt") as af:
                auth = af.readline().strip()
            headers["Cookie"] = (
                f"scauth={auth}; Expires=Mon, 01-Jun-2037 00:00:00 GMT; Path=/"
            )
            logging.debug(f"Got auth: {auth}")
        except Exception as ex:
            logging.info(f"Unable to read auth file: {ex}")

    if not auth:
        auth = get_auth_cookie()
        with open(authfile, "wt") as af:
            af.write(auth)
