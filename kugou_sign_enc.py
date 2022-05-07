import binascii
import json
import re
import hashlib
import uuid
import requests
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
        print("\nkey:{0}\niv：{1}\n".format(self.key, self.iv))
        crypt = generator.encrypt(self.PADDING(text).encode('utf-8'))
        # crypted_str = base64.b64encode(crypt)   #输出Base64
        crypted_str = binascii.b2a_hex(crypt)  # 输出Hex
        result = crypted_str.decode()
        return result.upper()

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
    t1 = int(round(t))
    t = int(round(t * 1000))
    print("clienttime_ms: {}".format(t))
    print("clienttime: {}".format(t1))

    # params sign
    key = get_random_bytes(16).hex()
    # key = "0E88FE37F53E7E0C609C2C7B4F115B2A"
    # t = "1650509161270"
    # t1 = "1650509161"
    i_key = hashlib.md5(key.encode()).hexdigest()
    aes = AESCBC(i_key.encode())
    params_encrypt = '{{"username":"13062581668","clienttime_ms":"{}","pwd":"123456789"}}'.format(t)
    params_data = aes.encrypt(params_encrypt)
    print("\nparams加密前:{0}\nparams加密后：{1}\n".format(params_encrypt, params_data))

    # pk sign
    message = '{{"clienttime_ms":"{}","key":"{}"}}'.format(t, key)
    msg = RsaNopadding(
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD2DT4odzkDd7hMlZ7djdZQH12j38nKxriINW1MGjMry3tXheya113xwmbBOwN0GA4zTwKFauFJRzcsD0nDFq1eaatcFKeDF25R4dnQRX+4BdTwFVS8lIb8nJMluSBwK+i4Z3VF+gfZ0AqQOXda6lJ4jPBt9Ep7VXEAHXUDn9JM8wIDAQAB")
    pk_data = msg.encrypt(message)
    print("\npk加密前:{0}\npk加密后：{1}\n".format(message, pk_data))

    # t1 sign
    t1_encrypt = "|{}".format(t + 100)
    # t1_encrypt = "|1650506454427"
    key = bytes.fromhex('6264656165643234333139336365313161633931336262643438643334306134')
    aes = AESCBC(key)
    t1_data = aes.encrypt(t1_encrypt)
    print("\nt1加密前:{0}\nt1加密后：{1}\n".format(t1_encrypt, t1_data))

    # t2 sign
    t2_encrypt = "5c539aee628111af4fc4645c761885bf|5c539aee628111af4fc4645c761885bf|9eea2d301e53|Pixel 4|{}".format(
        t + 10)
    # t2_encrypt = "5c539aee628111af4fc4645c761885bf|5c539aee628111af4fc4645c761885bf|9eea2d301e53|Pixel 4|1650506454441"
    key = bytes.fromhex('6463386531323366303736333661343133363162363232333566633331336163')
    aes = AESCBC(key)
    t2_data = aes.encrypt(t2_encrypt)
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
        "username": "130*****668"
    }

    # signature
    s = "4lu0l3cujt2KWIjcM374F8oX5N2lGY59appid=1131clienttime={}clientver=55400dfid=1tRbIu1gsMjC2Htvln120WPpmid=5c539aee628111af4fc4645c761885bfuuid=5c539aee628111af4fc4645c761885bf".format(
        t1) + str(login_data).replace("\'", "\"") + "4lu0l3cujt2KWIjcM374F8oX5N2lGY59"
    signature_data = hashlib.md5(s.encode()).hexdigest()
    print("\nsignature加密前:{0}\nsignature加密后：{1}\n".format(s, signature_data))

    # login
    url = 'https://loginservice.kugou.com/v9/login_by_pwd?appid=1131&clienttime={}&clientver=55400&dfid=1tRbIu1gsMjC2Htvln120WPp&mid=5c539aee628111af4fc4645c761885bf&uuid=5c539aee628111af4fc4645c761885bf&signature={}'.format(
        t1, signature_data)
    uid4 = uuid.uuid4()
    header = {
        "user-agent": "Android10-Phone-201-0-FANet-wifi",
        "accept-encoding": "gzip, deflate",
        "kg-rc": "1",
        "kg-thash": "c7ecef3",
        # "verifydata": "params={};pk={}".format(params_data, pk_data),
        "reqno": str(uid4),
        "content-type": "application/json"
    }
    proxies = {"http": None, "https": None}
    r = requests.post(url=url, headers=header, data=json.dumps(login_data), proxies=proxies)
    ret_data = r.text
    print(ret_data)
    ssa_code = r.headers["ssa-code"]
    print("ssa_code:{}".format(ssa_code))
    sign_str = "4lu0l3cujt2KWIjcM374F8oX5N2lGY59appid1131clientver55400eventid{}imei5c539aee628111af4fc4645c761885bfmacAddress-mid5c539aee628111af4fc4645c761885bfregisterTime0timestamp{}userid0xForwardedForxxxxxx4lu0l3cujt2KWIjcM374F8oX5N2lGY59".format(
        ssa_code, t1)
    sign_data = hashlib.md5(sign_str.encode()).hexdigest()
    print("\nsign加密前:{0}\nsign加密后：{1}\n".format(sign_str, sign_data))
    verify_code_data = {
        "eventid": ssa_code,
        "macAddress": "-",
        "registerTime": "0",
        "appid": "1131",
        "sign": sign_data,
        "imei": "5c539aee628111af4fc4645c761885bf",
        "mid": "5c539aee628111af4fc4645c761885bf",
        "clientver": "55400",
        "xForwardedFor": "xxxxxx",
        "android_id": "5c539aee628111af4fc4645c761885bf",
        "userid": "0",
        "timestamp": t1
    }

    verify_headers = {
        "User-Agent": "Android10-Phone-201-0-FANet-wifi",
        "Accept-Encoding": "gzip, deflate",
        "KG-RC": "1",
        "reqNo": str(uid4)
    }

    if json.loads(ret_data)["data"] in "请验证":
        print("verify")
        verify_url = "http://verifycode.service.kugou.com/v1/get_verify_info"
        verify_rsp = requests.post(url=verify_url, data=json.dumps(verify_code_data))
        print(verify_rsp.text)
