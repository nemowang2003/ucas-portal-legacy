import json
import logging
import typing
from functools import cached_property

import requests


class UCASPortalException(Exception):
    pass


class UCASPortalClient:
    def __init__(self, username: bytes, password: bytes) -> None:
        self.username = username
        self.password = password

        self.session = requests.Session()
        self.session.trust_env = False
        self._ip: str | None = None
        self._online: bool | None = None

    @property
    def ip(self) -> str:
        if self._ip is None:
            self._rad_user_info()
        return typing.cast(str, self._ip)

    @property
    def online(self) -> bool:
        if self._online is None:
            self._rad_user_info()
        return typing.cast(bool, self._online)

    def login(self) -> None:
        if self.online:
            return

        challenge = self._get_challenge()
        encrypted_password = self.hmd5(self.password, challenge.encode())
        info = self._calc_info(challenge)
        chksum = self._calc_chksum(challenge, encrypted_password, info)

        response = self._get(
            "https://portal.ucas.ac.cn/cgi-bin/srun_portal",
            params=[
                (b"action", b"login"),
                (b"callback", b"_"),
                (b"username", self.username),
                (b"password", b"{MD5}" + encrypted_password),
                (b"os", b"Windows"),
                (b"name", b"Windows"),
                (b"nas_ip", b""),
                (b"double_stack", b"0"),
                (b"chksum", chksum),
                (b"info", info),
                (b"ac_id", b"1"),
                (b"ip", self.ip),
                (b"n", b"200"),
                (b"type", b"1"),
                (b"captchaVal", b""),
                (b"_", b"0"),
            ],
        )
        self._online = response["error"] == "ok"
        if not self._online:
            raise UCASPortalException("Login failed.")

    def logout(self):
        if not self.online:
            return

        response = self._get(
            "https://portal.ucas.ac.cn/cgi-bin/srun_portal?action=logout&callback=_"
        )
        self._online = response["error"] != "ok"
        if self._online:
            raise UCASPortalException("Logout failed.")

    def _rad_user_info(self):
        response = self._get("https://portal.ucas.ac.cn/cgi-bin/rad_user_info?callback=_")
        self._ip = response["online_ip"]
        self._online = response["error"] != "not_online_error"

    def _get_challenge(self) -> str:
        return self._get(
            "https://portal.ucas.ac.cn/cgi-bin/get_challenge?callback=_",
            params=[
                (b"username", self.username),
                (b"ip", self.ip),
            ],
        )["challenge"]

    def _get(self, url, **kwargs) -> dict:
        kwargs.setdefault("timeout", 3)
        response = json.loads(self.session.get(url, **kwargs).text[2:-1])
        logging.debug(f"[ucas_login.client] {url=} {response=}")
        return response

    def _calc_info(self, challenge: str) -> bytes:
        import base64

        json_data = json.dumps(
            {
                "username": self.username.decode(),
                "password": self.password.decode(),
                "ip": self.ip,
                "acid": "1",
                "enc_ver": "srun_bx1",
            },
            separators=(",", ":"),
        )
        result = base64.b64encode(self.xxtea_encrypt(json_data.encode(), challenge.encode()))
        return b"{SRBX1}" + result.translate(self.base64_translate_table)

    @cached_property
    def base64_translate_table(self) -> bytes:
        return bytes.maketrans(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            b"LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA",
        )

    def _calc_chksum(self, challenge: str, encrypted_password: bytes, info: bytes) -> bytes:
        return self.sha1(
            challenge.encode().join(
                [
                    b"",
                    self.username,
                    encrypted_password,
                    b"1",
                    self.ip.encode(),
                    b"200",
                    b"1",
                    info,
                ]
            )
        )

    @staticmethod
    def hmd5(msg: bytes, key: bytes) -> bytes:
        import binascii
        import hashlib
        import hmac

        return binascii.b2a_hex(hmac.new(key, msg, hashlib.md5).digest())

    @staticmethod
    def sha1(msg: bytes) -> bytes:
        import binascii
        import hashlib

        return binascii.b2a_hex(hashlib.sha1(msg).digest())

    @staticmethod
    def xxtea_encrypt(data: bytes, key: bytes) -> bytes:
        import array

        if not data:
            return b""

        # 预处理 data: 将 bytes 转为 u32 的 array, 也就是 "I" 模式
        # 如果 data 长度不是 4 的倍数，先补零对齐
        original_data_len = len(data)
        remainder = original_data_len % 4
        if remainder != 0:
            data += b"\0" * (4 - remainder)
        v = array.array("I", data)
        v.append(original_data_len)  # 在末尾存入长度信息

        # 预处理 key
        # 确保 key 至少 16 字节，并转为 u32 的 array
        if len(key) < 16:
            key += b"\0" * (16 - len(key))
        k = array.array("I", key[:16])

        n = len(v)
        z = v[n - 1]
        sum_val = 0
        for _ in range(6 + 52 // n):
            sum_val += 0x9E3779B9
            sum_val &= 0xFFFFFFFF
            e = (sum_val >> 2) & 3
            for p in range(n):
                y = v[(p + 1) % n]  # 当 p 为 n-1 时 y 为 v[0]
                m = z >> 5 ^ y << 2
                m += y >> 3 ^ z << 4 ^ (sum_val ^ y)
                m &= 0xFFFFFFFF
                m += k[(p & 3) ^ e] ^ z
                m &= 0xFFFFFFFF
                v[p] += m
                v[p] &= 0xFFFFFFFF
                z = v[p]

        return bytes(v)
