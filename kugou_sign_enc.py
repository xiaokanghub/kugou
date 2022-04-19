import binascii
import json
import re
import hashlib
import rsa
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time


def zfillStrToBin(s):
    b = bytes(s.encode())
    for i in range(128 - len(b)):
        b += b'\0'
    # print(len(b))
    return b


class AESCBC:
    def __init__(self, init_key):
        self.key = init_key
        self.iv = self.key[16:32]
        self.mode = AES.MODE_CBC
        self.bs = 16  # block size
        self.PADDING = lambda s: s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def encrypt(self, text):
        generator = AES.new(self.key, self.mode, self.iv)
        print("\nkey:{0}\niv：{1}\n".format(self.key.hex(), self.iv.hex()))
        crypt = generator.encrypt(self.PADDING(text).encode('utf-8'))
        # crypted_str = base64.b64encode(crypt)   #输出Base64
        crypted_str = binascii.b2a_hex(crypt)  # 输出Hex
        result = crypted_str.decode()
        return self.key.hex(), result.upper()

    def decrypt(self, text):
        generator = AES.new(self.key, self.mode, self.iv)
        text += (len(text) % 4) * '='
        # decrpyt_bytes = base64.b64decode(text)           #输出Base64
        decrpyt_bytes = binascii.a2b_hex(text)  # 输出Hex
        meg = generator.decrypt(decrpyt_bytes)
        # 去除解码后的非法字符
        try:
            result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f\n\r\t]').sub('', meg.decode())
        except Exception:
            result = '解码失败，请重试!'
        return result


class RsaNopadding:

    def __init__(self, key):
        self.pubkey = RSA.importKey(base64.b64decode(key))

    def encrypt(self, message):
        kLen = rsa.common.byte_size(self.pubkey.n)
        msg = zfillStrToBin(message)
        _b = rsa.transform.bytes2int(msg)
        _i = rsa.core.encrypt_int(_b, self.pubkey.e, self.pubkey.n)
        result = rsa.transform.int2bytes(_i, kLen)
        return result.hex().upper()


if __name__ == '__main__':
    # clienttime_ms
    t = time.time()
    t = int(round(t * 1000))
    print("clienttime_ms: {}".format(t))

    # params sign
    aes = AESCBC(get_random_bytes(32))
    params_encrypt = '{{"username":"13062581696","clienttime_ms":"{}","pwd":"557998555"}}'.format(t)
    key, params_data = aes.encrypt(params_encrypt)
    print("\nparams加密前:{0}\nparams加密后：{1}\n".format(params_encrypt, params_data))

    # pk sign
    message = '{{"clienttime_ms":"{}","key":"{}"}}'.format(t, key)
    msg = RsaNopadding(
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD2DT4odzkDd7hMlZ7djdZQH12j38nKxriINW1MGjMry3tXheya113xwmbBOwN0GA4zTwKFauFJRzcsD0nDFq1eaatcFKeDF25R4dnQRX+4BdTwFVS8lIb8nJMluSBwK+i4Z3VF+gfZ0AqQOXda6lJ4jPBt9Ep7VXEAHXUDn9JM8wIDAQAB")
    pk_data = msg.encrypt(message)
    print("\npk加密前:{0}\npk加密后：{1}\n".format(message, pk_data))

    # t1 sign
    t1_encrypt = "|{}".format(t)
    key = bytes.fromhex('bdeaed243193ce11ac913bbd48d340a4'.encode().hex())
    aes = AESCBC(key)
    key, t1_data = aes.encrypt(t1_encrypt)
    print("\nt1加密前:{0}\nt1加密后：{1}\n".format(t1_encrypt, t1_data))

    # t2 sign
    t2_encrypt = "||9eea2d301e53|Pixel 4|{}".format(t)
    key = bytes.fromhex('dc8e123f07636a41361b62235fc313ac'.encode().hex())
    aes = AESCBC(key)
    key, t2_data = aes.encrypt(t2_encrypt)
    print("\nt2加密前:{0}\nt2加密后：{1}\n".format(t2_encrypt, t2_data))

    # key sign
    k = "11314lu0l3cujt2KWIjcM374F8oX5N2lGY5955400{}".format(t)
    key_data = hashlib.md5(k.encode()).hexdigest()
    print("\nkey加密前:{0}\nkey加密后：{1}\n".format(k, key_data))

    # login data
    login_data = {
        "params": params_data,
        "clienttime_ms": t,
        "support_face_verify": "1",
        "dfid": "1tRbIu1gsMjC2Htvln120WPp",
        "dev": "Pixel%204",
        "plat": "1",
        "pk": pk_data,
        "t1": t1_data,
        "support_verify": "1",
        "support_multi": "1",
        "t2": t2_data,
        "key": key_data,
        "username": "130*****669"
    }

    # signature
    s = "4lu0l3cujt2KWIjcM374F8oX5N2lGY59appid=1131clienttime={}clientver=55400dfid=1tRbIu1gsMjC2Htvln120WPpmid=5c539aee628111af4fc4645c761885bfuuid=5c539aee628111af4fc4645c761885bf".format(
        t) + str(login_data) + "4lu0l3cujt2KWIjcM374F8oX5N2lGY59"
    signature_data = hashlib.md5(s.encode()).hexdigest()
    print("\nsignature加密前:{0}\nsignature加密后：{1}\n".format(s, signature_data))

