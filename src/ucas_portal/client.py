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

        # 1. 预处理数据：将 bytes 直接转为 32位无符号整数数组 ('I')
        # 如果 data 长度不是 4 的倍数，先补零对齐
        n = len(data)
        padding = (4 - n % 4) % 4
        if padding:
            data += b"\0" * padding

        v = array.array("I", data)
        v.append(n)  # 在末尾存入长度信息

        # 2. 预处理 Key
        # 确保 key 至少 16 字节，并转为 array
        if len(key) < 16:
            key += b"\0" * (16 - len(key))
        k = array.array("I", key[:16])

        # 3. 初始化变量
        n_idx = len(v) - 1
        z = v[n_idx]
        y = v[0]
        delta = 0x9E3779B9
        q = 6 + 52 // (n_idx + 1)
        sum_val = 0

        # 4. 加密循环
        while q > 0:
            sum_val = (sum_val + delta) & 0xFFFFFFFF
            e = (sum_val >> 2) & 3

            # 内部循环：处理前 n-1 个字节
            p = 0
            while p < n_idx:
                y = v[p + 1]
                m = z >> 5 ^ y << 2
                m = (m + (y >> 3 ^ z << 4 ^ (sum_val ^ y))) & 0xFFFFFFFF
                m = (m + (k[(p & 3) ^ e] ^ z)) & 0xFFFFFFFF

                v[p] = (v[p] + m) & 0xFFFFFFFF
                z = v[p]
                p += 1

            # 最后一轮处理：处理第 n 个字节
            y = v[0]
            m = z >> 5 ^ y << 2
            m = (m + (y >> 3 ^ z << 4 ^ (sum_val ^ y))) & 0xFFFFFFFF
            m = (m + (k[(p & 3) ^ e] ^ z)) & 0xFFFFFFFF

            v[n_idx] = (v[n_idx] + m) & 0xFFFFFFFF
            z = v[n_idx]
            q -= 1

        return bytes(v)
