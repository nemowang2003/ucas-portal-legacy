import json
import requests

CALLBACK = "_"
TYPE = "1"
N = "200"
ENC_VER = "srun_bx1"
ACID = "1"
OS = "Windows"


def translate_b64encode(msg: bytes, alpha: str) -> str:
    import base64

    assert len(alpha) == 64
    result = base64.b64encode(msg).decode()
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    trans_table = str.maketrans(table, alpha)
    return result.translate(trans_table)


def calc_info(info: dict, token: str) -> str:
    import xxtea

    alpha = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
    json_data = json.dumps(info, separators=(",", ":"))
    result = translate_b64encode(xxtea.encrypt(json_data, token), alpha)
    return "{SRBX1}" + result


def hmd5(msg: str, key: str) -> str:
    import hashlib
    import hmac

    return hmac.new(key.encode(), msg.encode(), hashlib.md5).hexdigest()


def sha1(msg) -> str:
    import hashlib

    return hashlib.sha1(msg.encode()).hexdigest()


def chkstr(
    token: str, username: str, encrypted_password: str, ip: str, info: str
) -> str:
    return token.join(["", username, encrypted_password, ACID, ip, N, TYPE, info])


class LoginSession:
    def __init__(self):
        self.session = requests.Session()
        self.session.trust_env = False

    def get(self, *args, **kwargs) -> dict:
        kwargs.setdefault("timeout", 3)
        response = self.session.get(*args, **kwargs).text
        return json.loads(response[len(CALLBACK) + 1 : -1])

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()


def main() -> None:
    import time

    with LoginSession() as session:
        session.trust_env = False

        response = session.get(
            "https://portal.ucas.ac.cn/cgi-bin/rad_user_info",
            params={"callback": CALLBACK},
        )
        if response["error"] != "not_online_error":
            return
        ip = response["online_ip"]

        import os

        username = os.environ["UCAS_LOGIN_USERNAME"]
        password = os.environ["UCAS_LOGIN_PASSWORD"]
        challenge = session.get(
            "https://portal.ucas.ac.cn/cgi-bin/get_challenge",
            params={"callback": CALLBACK, "username": username, "ip": ip},
        )["challenge"]

        enctypted_password = hmd5(password, challenge)
        info = calc_info(
            {
                "username": username,
                "password": password,
                "ip": ip,
                "acid": ACID,
                "enc_ver": ENC_VER,
            },
            challenge,
        )
        chksum = sha1(
            chkstr(
                challenge,
                username,
                enctypted_password,
                ip,
                info,
            )
        )

        response = session.get(
            "https://portal.ucas.ac.cn/cgi-bin/srun_portal",
            params={
                "action": "login",
                "callback": CALLBACK,
                "username": username,
                "password": "{MD5}" + enctypted_password,
                "os": OS,
                "name": OS,
                "nas_ip": "",
                "double_stack": 0,
                "chksum": chksum,
                "info": info,
                "ac_id": ACID,
                "ip": ip,
                "n": N,
                "type": TYPE,
                "captchaVal": "",
                "_": int(time.time() * 1000),
            },
        )
        if response["error"] != "ok":
            import sys

            sys.exit(1)
