#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trae AutoCheckin · Trae 每日自动签到（抗 9074 限流版）
────────────────────────────────────────────────────────────
账号来源优先读脚本同目录 !trae.json，存在即忽略环境变量账号配置。

📦 环境变量（!trae.json 不存在时使用）
  TRAE_ACCOUNTS / TRAE_REFRESH_TOKEN[_N] / TRAE_ACCESS_TOKEN / TRAE_ICUBE_AUTH 等
  QYWX_TOKEN / WECHAT_WEBHOOK / PLUSPLUS_TOKEN 等推送配置不受影响
"""

import base64, glob, hashlib, json, os, platform, random, re, sys, time, urllib.request, urllib.error

UgHost = 'https://api.trae.cn'
OAuthHost = 'https://api.trae.com.cn'
ClientID = 'en1oxy7wnw8j9n'
ClientIDIde = os.getenv('TRAE_CLIENT_ID', '').strip() or 'ono9krqynydwx5'
IdeVersion = '1.107.1'
UA = 'Trae/%s' % IdeVersion
EP_STATUS = UgHost + '/trae/api/v2/ug/checkin_credits/status'
EP_CLAIM = UgHost + '/trae/api/v2/ug/checkin_credits/claim'
EP_EXCHANGE = OAuthHost + '/cloudide/api/v3/trae/oauth/ExchangeToken'
EP_EXCHANGE_PROOF = UgHost + '/trae/api/v3/oauth/ExchangeToken'
EP_ENTITLE = UgHost + '/trae/api/v2/pay/user_current_entitlement_list'
AUTH_FAIL_CODES = (1001, 1002, 401, 403)
RATE_HTTP_CODES = (429, 500, 502, 503, 504)
RATE_CODE = 9074
REQ_SOURCE = 1
REQ_BODY = '{"req_source": %d}' % REQ_SOURCE
ALREADY_CODE = 9095
QYWX_URL = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key='
PUSHPLUS_URL = 'https://www.pushplus.plus/send'

PLUSPLUS_TOKEN = os.getenv('PLUSPLUS_TOKEN', '')
QYWX_TOKEN = os.getenv('QYWX_TOKEN') or os.getenv('WECHAT_WEBHOOK') or ''

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_ACCOUNTS_FILE = os.path.join(HERE, '!trae.json')
DEVICE_ID_FILE = os.path.join(HERE, '.trae_device_ids.json')
STATE_FILE = os.path.join(HERE, '.trae_checkin_state.json')
TOKEN_CACHE_FILE = os.path.join(HERE, '.trae_token_cache.json')


# ══════════════════ tc 解密 ══════════════════
SALT_A = bytes([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
                124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
                84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
                8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37])
SALT_B = bytes([31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
                96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
                160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
                23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125])
SALT_C = bytes([191, 192, 216, 250, 122, 246, 220, 97, 31, 254, 98, 27, 8, 72, 71, 176,
                135, 99, 96, 18, 127, 101, 203, 104, 211, 102, 191, 125, 37, 72, 150, 156,
                51, 229, 121, 35, 17, 153, 141, 177, 110, 131, 150, 128, 172, 255, 254, 6,
                18, 140, 55, 62, 236, 249, 135, 64, 135, 12, 117, 4, 89, 149, 168, 209])
SALT_D = bytes([246, 204, 26, 232, 232, 70, 129, 109, 223, 146, 169, 242, 23, 241, 105, 145,
                50, 196, 165, 42, 254, 120, 3, 54, 244, 207, 209, 85, 53, 6, 138, 106,
                175, 148, 31, 204, 186, 186, 165, 182, 87, 142, 49, 10, 39, 110, 26, 154,
                86, 56, 173, 125, 18, 64, 198, 225, 99, 99, 83, 82, 191, 134, 76, 170])
SALT_AES = bytes(a ^ b for a, b in zip(SALT_A, SALT_B))
SALT_AES_PRIVATE = bytes(a ^ b for a, b in zip(SALT_C, SALT_D))
STORAGE_KEY = 'iCubeAuthInfo://icube.cloudide'


def enc_type_of(header):
    if header[0:6] == bytes([0x74, 0x63, 0x05, 0x10, 0x00, 0x00]):
        return 'AES'
    if header[0:6] == bytes([18, 57, 32, 32, 2, 3]):
        return 'AES_PRIVATE'
    return 'UNKNOWN'


def key_iv_of(random_bytes, enc_type):
    salt = SALT_AES_PRIVATE if enc_type == 'AES_PRIVATE' else SALT_AES
    final_hash = hashlib.sha512(hashlib.sha512(random_bytes).digest() + salt).digest()
    return final_hash[0:16], final_hash[16:32]


def decrypt_storage_value(base64_value):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise SystemExit('❌ 解密 icubeAuth/storage.json 需要 cryptography，'
                         '请 pip install cryptography；'
                         '或改用 accessToken/refreshToken 方式配置账号（零依赖）')
    buf = base64.b64decode(base64_value)
    enc_type = enc_type_of(buf[0:6])
    if enc_type == 'UNKNOWN':
        raise ValueError('未知的加密类型 (前 6 字节=%s)' % buf[0:6].hex())
    key, iv = key_iv_of(buf[6:38], enc_type)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    decrypted = dec.update(buf[38:]) + dec.finalize()
    stored_hash, plaintext = decrypted[0:64], decrypted[64:]
    pad = plaintext[-1] if plaintext else 0
    if 1 <= pad <= 16:
        plaintext = plaintext[:-pad]
    else:
        plaintext = plaintext.rstrip(b'\x00').rstrip()
    if stored_hash != hashlib.sha512(plaintext).digest():
        raise ValueError('SHA-512 校验失败，解密可能不正确')
    return plaintext.decode('utf-8')


_DEVICE_ID_RE = re.compile(r'^\d{12,20}$')


def is_valid_device_id(d):
    return bool(_DEVICE_ID_RE.match(str(d or '').strip()))


def dc_device_id(storage):
    for k, v in storage.items():
        if k.startswith('iCubeAuthInfo://icube-dc:'):
            d = k[len('iCubeAuthInfo://icube-dc:'):].strip()
            if is_valid_device_id(d):
                return d
        elif k.rstrip(':') == 'iCubeAuthInfo://icube-dc' and is_valid_device_id(v):
            return str(v).strip()
    return ''


def find_storage_json():
    home = os.path.expanduser('~')
    names = ('Trae CN', 'TRAE SOLO CN', 'TRAE SOLO', 'Trae')
    sub = ('User', 'globalStorage', 'storage.json')
    candidates = []
    appdata = os.environ.get('APPDATA') or os.path.join(home, 'AppData', 'Roaming')
    for n in names:
        candidates.append(os.path.join(appdata, n, *sub))
    lib = os.path.join(home, 'Library', 'Application Support')
    for n in names:
        candidates.append(os.path.join(lib, n, *sub))
    for base in (home, os.path.join(home, '.config')):
        for n in ('.trae-cn', '.trae', 'Trae CN', 'TRAE SOLO CN'):
            candidates.append(os.path.join(base, n, *sub))
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def load_from_storage(storage_path):
    with open(storage_path, 'r', encoding='utf-8') as fh:
        storage = json.load(fh)
    enc = (storage.get(STORAGE_KEY) or '').strip()
    if not enc:
        raise ValueError('storage.json 里找不到 %s' % STORAGE_KEY)
    if enc.startswith('{'):
        return json.loads(enc), dc_device_id(storage)
    return json.loads(decrypt_storage_value(enc)), dc_device_id(storage)


# ══════════════════ 缓存文件 ══════════════════
def _cache_path():
    p = os.environ.get('TRAE_TOKEN_CACHE', '').strip()
    if p:
        return p
    for cand in ('/ql/data/config/.trae_token_cache.json', TOKEN_CACHE_FILE):
        d = os.path.dirname(cand)
        if d and os.path.isdir(d):
            return cand
    return TOKEN_CACHE_FILE


def load_cache():
    try:
        with open(_cache_path(), 'r', encoding='utf-8') as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_cache(cache):
    try:
        path = _cache_path()
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(cache, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        print('⚠️  [缓存] 写入失败:', e)


def put_cache(cache, acc):
    key = _acct_key(acc)
    if not (key and acc.get('accessToken')):
        return
    cache[key] = {'accessToken': acc['accessToken'],
                  'refreshToken': acc.get('refreshToken', ''),
                  'expiresAt': _jwt_exp(acc['accessToken']),
                  'updatedAt': int(time.time())}
    save_cache(cache)


def apply_cache(accounts, cache=None):
    cache = load_cache() if cache is None else cache
    if not cache:
        return accounts
    by_uid = {}
    for k, rec in cache.items():
        if not isinstance(rec, dict):
            continue
        at = rec.get('accessToken') or ''
        rt = rec.get('refreshToken') or ''
        if not (at and rt):
            continue
        u = _jwt_uid(at) or str(k)
        exp = int(rec.get('expiresAt') or 0)
        if u not in by_uid or exp > by_uid[u][0]:
            by_uid[u] = (exp, rec)
    hit = 0
    for a in accounts:
        rec = None
        for key in (_acct_key(a), str(a.get('uid') or '').strip()):
            if key and key in by_uid:
                rec = by_uid[key][1]
                break
        if rec and rec.get('accessToken'):
            if int(rec.get('expiresAt') or 0) >= _jwt_exp(a.get('accessToken') or ''):
                a['accessToken'] = rec['accessToken']
                if rec.get('refreshToken'):
                    a['refreshToken'] = rec['refreshToken']
                hit += 1
    if hit:
        print('🔁 [缓存] 已用上次续期的 token 覆盖 %d 个账号' % hit)
    return accounts


# ══════════════════ 时间与当日状态 ══════════════════
def bj_now():
    return time.gmtime(time.time() + 8 * 3600)


def bj():
    return time.strftime('%Y-%m-%d %H:%M:%S', bj_now())


def today_str():
    return time.strftime('%Y-%m-%d', bj_now())


def load_state():
    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as fh:
            st = json.load(fh)
    except Exception:
        st = {}
    if st.get('date') != today_str():
        st = {'date': today_str(), 'done': {}, 'cooldown': {}}
    st.setdefault('done', {})
    st.setdefault('cooldown', {})
    return st


def mark_done(key, info):
    st = load_state()
    st['done'][str(key)] = info
    try:
        with open(STATE_FILE, 'w', encoding='utf-8') as fh:
            json.dump(st, fh, ensure_ascii=False, indent=2)
    except Exception as e:
        print('⚠️  [状态] 写入失败:', e)


def cooldown_minutes():
    env = 'TRAE_PEAK_COOLDOWN_MIN' if in_peak_hour() else 'TRAE_COOLDOWN_MIN'
    try:
        return max(1, int(os.getenv(env, str(PEAK_COOLDOWN_MIN if in_peak_hour() else COOLDOWN_MIN))))
    except Exception:
        return PEAK_COOLDOWN_MIN if in_peak_hour() else COOLDOWN_MIN


def set_cooldown(key, minutes):
    st = load_state()
    st['cooldown'][str(key)] = time.strftime('%Y-%m-%d %H:%M', time.localtime(time.time() + minutes * 60))
    try:
        with open(STATE_FILE, 'w', encoding='utf-8') as fh:
            json.dump(st, fh, ensure_ascii=False, indent=2)
    except Exception as e:
        print('⚠️  [冷却] 写入失败: %s' % e)


def cooldown_left(key, state=None):
    st = state if state is not None else load_state()
    until = (st.get('cooldown') or {}).get(str(key)) or ''
    try:
        ts = time.mktime(time.strptime(until, '%Y-%m-%d %H:%M'))
    except Exception:
        return 0
    return max(0, int(ts - time.time()))


def _acct_key(acc):
    return (str(acc.get('uid') or '').strip()
            or str(acc.get('_name') or '').strip()
            or str(acc.get('name') or '').strip()
            or 'default')


# ══════════════════ 日志与图标 ══════════════════
BOX = 52


def _wlen(s):
    n = 0
    for ch in s:
        o = ord(ch)
        n += 2 if (0x1100 <= o <= 0x115F or 0x2E80 <= o <= 0xA4CF or 0xAC00 <= o <= 0xD7A3
                   or 0xF900 <= o <= 0xFAFF or 0xFE30 <= o <= 0xFE6F or 0xFF00 <= o <= 0xFF60
                   or 0x1F300 <= o <= 0x1FAFF) else 1
    return n


def log_cell(s):
    body = ' ' + s
    print('║' + body + ' ' * max(0, BOX - _wlen(body)) + '║')


def log_box(lines, top=''):
    print()
    print('╔' + '═' * BOX + '╗')
    for s in ([top] if top else []) + list(lines):
        log_cell(s)
    print('╚' + '═' * BOX + '╝')


def log_title(total):
    log_box(['🕒 启动时间: ' + bj(), '👥 账号数量: %s' % total],
            '🤖 Trae SOLO 每日签到脚本（多账号）')


def log_head(title):
    body = ' ' + title
    print()
    print('┌' + '─' * BOX + '┐')
    print('│' + body + ' ' * max(0, BOX - _wlen(body)) + '│')
    print('└' + '─' * BOX + '┘')


# ══════════════════ HTTP ══════════════════
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _post(url, headers, body='{}', timeout=30):
    req = urllib.request.Request(url, data=(body.encode('utf-8') if isinstance(body, str) else body),
                                 headers=headers, method='POST')
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return -1, str(e)


def ug_headers(token, device_id):
    headers = {'Authorization': 'Cloud-IDE-JWT ' + token, 'X-User-Region': 'CN',
               'User-Agent': UA, 'Content-Type': 'application/json'}
    if device_id:
        headers['x-device-id'] = device_id
    headers['x-device-type'] = platform.system() or 'Windows'
    headers['x-os-version'] = platform.version() or '10.0.19045'
    headers['x-app-version'] = IdeVersion
    brand = os.getenv('TRAE_DEVICE_BRAND', '').strip()
    if brand:
        headers['x-device-brand'] = brand
    return headers


# ══════════════════ 设备证明（纯标准库 ECDSA P-256） ══════════════════
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = P256_P - 3
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def _der_tlv(buf, i):
    tag = buf[i]; i += 1
    ln = buf[i]; i += 1
    if ln & 0x80:
        n = ln & 0x7f
        ln = int.from_bytes(buf[i:i + n], 'big'); i += n
    return tag, buf[i:i + ln], i + ln


def _pem_der(pem):
    body = ''.join(l.strip() for l in pem.splitlines() if '---' not in l)
    return base64.b64decode(body)


def ec_private_scalar(pem):
    der = _pem_der(pem)
    try:
        _, body, _ = _der_tlv(der, 0)
        i = 0
        _, _, i = _der_tlv(body, i)
        _, _, i = _der_tlv(body, i)
        _, octs, i = _der_tlv(body, i)
        _, inner, _ = _der_tlv(octs, 0)
        j = 0
        _, _, j = _der_tlv(inner, j)
        _, d, j = _der_tlv(inner, j)
        return int.from_bytes(d, 'big')
    except Exception:
        _, body, _ = _der_tlv(der, 0)
        i = 0
        _, _, i = _der_tlv(body, i)
        _, d, i = _der_tlv(body, i)
        return int.from_bytes(d, 'big')


def _ec_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P256_P == 0: return None
    if p1 == p2:
        lam = (3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P) % P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    return x3, (lam * (x1 - x3) - y1) % P256_P


def _ec_mul(k, pt):
    r = None
    while k:
        if k & 1: r = _ec_add(r, pt)
        pt = _ec_add(pt, pt)
        k >>= 1
    return r


def _der_sig(r, s):
    def enc(x):
        b = x.to_bytes(32, 'big').lstrip(b'\x00') or b'\x00'
        if b[0] & 0x80: b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b'\x30' + bytes([len(body)]) + body


def ec_sign(pem, data):
    d = ec_private_scalar(pem)
    z = int.from_bytes(hashlib.sha256(data).digest(), 'big')
    while True:
        k = int.from_bytes(os.urandom(32), 'big') % (P256_N - 1) + 1
        x1, _ = _ec_mul(k, (P256_GX, P256_GY))
        r = x1 % P256_N
        if r == 0: continue
        s = (pow(k, -1, P256_N) * (z + r * d)) % P256_N
        if s == 0: continue
        if s > P256_N // 2: s = P256_N - s
        return base64.b64encode(_der_sig(r, s)).decode('ascii')


def local_device_keys():
    sp = os.getenv('TRAE_STORAGE_PATH', '').strip() or find_storage_json()
    if not sp or not os.path.isfile(sp):
        return None
    try:
        with open(sp, 'r', encoding='utf-8') as fh:
            storage = json.load(fh)
        did = dc_device_id(storage)
        if not did:
            return None
        env = storage.get('iCubeAuthInfo://icube-dc:%s' % did)
        if not env:
            return None
        dev = json.loads(decrypt_storage_value(env.strip()))
        priv = (dev.get('privateKeyPEM') or '').strip()
        pub = (dev.get('publicKeyPEM') or '').strip()
        if not (priv and pub):
            return None
        return {'deviceId': did, 'privateKeyPem': priv, 'publicKeyPem': pub,
                'machineId': (storage.get('telemetry.machineId') or '').strip()}
    except Exception:
        return None


def norm_pem(v):
    v = (v or '').strip()
    if '\\n' in v and '\n' not in v:
        v = v.replace('\\n', '\n')
    return v


def device_keys_for(acc):
    priv = norm_pem(str(acc.get('deviceKeyPem') or '') or os.getenv('TRAE_DEVICE_KEY_PEM', ''))
    pub = norm_pem(str(acc.get('devicePubPem') or '') or os.getenv('TRAE_DEVICE_PUB_PEM', ''))
    did = str(acc.get('deviceId') or '').strip()
    mid = str(acc.get('machineId') or '').strip() or os.getenv('TRAE_MACHINE_ID', '').strip()
    if priv and pub and did:
        return {'deviceId': did, 'privateKeyPem': priv, 'publicKeyPem': pub, 'machineId': mid}
    local = local_device_keys()
    if local and priv and pub:
        local['privateKeyPem'] = priv
        local['publicKeyPem'] = pub
        return local
    return local


def device_proof(path, refresh_token, keys, client_id=None, platform_code='IDE_PC'):
    ts = int(time.time())
    nonce = os.urandom(16).hex()
    canonical = '\n'.join(['POST', path, client_id or ClientID, refresh_token, str(ts), nonce])
    proof = {'Timestamp': ts, 'Nonce': nonce,
             'Signature': ec_sign(keys['privateKeyPem'], canonical.encode('utf-8'))}
    info = {'DeviceID': keys.get('deviceId') or '', 'MachineID': keys.get('machineId') or '',
            'PlatformCode': platform_code, 'DeviceType': 'PC',
            'DeviceName': os.getenv('TRAE_DEVICE_NAME', '').strip() or platform.node() or 'PC',
            'DeviceModel': os.getenv('TRAE_DEVICE_MODEL', '').strip(),
            'ClientVersion': IdeVersion, 'DevicePublicKey': keys['publicKeyPem'],
            'DeviceBrand': os.getenv('TRAE_DEVICE_BRAND', '').strip(), 'DeviceCPU': '',
            'OSInfo': platform.system() or 'Windows', 'OSVersion': platform.release() or ''}
    return proof, info


# ══════════════════ Token 工具 ══════════════════
def refresh(refresh_token, keys=None):
    if keys and keys.get('privateKeyPem') and keys.get('publicKeyPem'):
        path = '/trae/api/v3/oauth/ExchangeToken'
        last = None
        combos = [(ClientIDIde, 'IDE_PC')]
        for pair in ((ClientID, 'IDE_PC'), (ClientID, 'SOLO_PC')):
            if pair not in combos:
                combos.append(pair)
        for cid, pcode in combos:
            try:
                proof, info = device_proof(path, refresh_token, keys, cid, pcode)
            except Exception as e:
                return None, None, '设备签名失败（检查设备私钥）: %s' % e
            body = json.dumps({'ClientID': cid, 'ClientSecret': '', 'RefreshToken': refresh_token,
                               'DeviceInfo': info, 'DeviceProof': proof, 'IDEVersion': IdeVersion})
            status, text = _post(EP_EXCHANGE_PROOF, {'Content-Type': 'application/json',
                                                     'x-cloudide-token': ''}, body)
            if status < 400:
                break
            last = (status, text)
            if '10101' not in text and '20403' not in text:
                break
        else:
            status, text = last or (status, text)
    else:
        body = json.dumps({'ClientID': ClientID, 'RefreshToken': refresh_token,
                           'ClientSecret': '-', 'UserID': ''})
        status, text = _post(EP_EXCHANGE, {'Content-Type': 'application/json',
                                           'Accept': 'application/json', 'User-Agent': UA}, body)
    if status >= 400 or status < 0:
        return None, None, 'refresh http=%s %s' % (status, _explain_refresh_err(text))
    try:
        res = json.loads(text)['Result']
        return res.get('Token'), res.get('RefreshToken'), 'ok'
    except Exception as e:
        return None, None, 'parse refresh: %s %s' % (e, text[:200])


def _explain_refresh_err(text):
    try:
        err = (json.loads(text).get('ResponseMetadata') or {}).get('Error') or {}
        code = err.get('Code')
        dirty = ((err.get('Data') or {}).get('__Message.error')) or err.get('Message') or ''
    except Exception:
        return text[:200]
    hint = {20101: 'refreshToken 已失效或被轮换掉了，请重新提取',
            10101: 'refreshToken 与客户端不匹配（可能被别处轮换过、或来自另一条产品线的客户端），请重新提取',
            20405: '服务端要求设备证明：请配置 TRAE_DEVICE_KEY_PEM / TRAE_DEVICE_PUB_PEM / TRAE_DEVICE_ID',
            20403: '设备与 token 不匹配：确认设备密钥是从签发该 token 的同一台机器导出的',
            }.get(code, '')
    return 'code=%s %s%s' % (code, dirty, ('（%s）' % hint) if hint else '')


def _jwt_uid(token):
    try:
        parts = token.split('.')
        pad = parts[1] + '=' * (-len(parts[1]) % 4)
        return str(json.loads(base64.urlsafe_b64decode(pad)).get('data', {}).get('id', ''))
    except Exception:
        return ''


def _jwt_exp(token):
    try:
        parts = token.split('.')
        pad = parts[1] + '=' * (-len(parts[1]) % 4)
        return int(json.loads(base64.urlsafe_b64decode(pad)).get('exp', 0))
    except Exception:
        return 0


def ensure_token(acc, cache):
    if not acc.get('refreshToken'):
        return False, '无 refreshToken，无法刷新'
    try:
        keys = device_keys_for(acc)
    except Exception:
        keys = None
    new_at, new_rt, msg = refresh(acc['refreshToken'], keys)
    if not new_at:
        return False, msg
    acc['accessToken'] = new_at
    if new_rt:
        acc['refreshToken'] = new_rt
    put_cache(cache, acc)
    persist_tokens(acc)
    return True, '已刷新 accessToken'


def persist_local_json(acc):
    """回写脚本同目录 !trae.json（本模式下的凭据来源）。
    refreshToken 是轮换链，若不回写，文件会一直停在被轮换掉的旧节点 → 另一方用旧值续期报 10101。"""
    if not os.path.isfile(LOCAL_ACCOUNTS_FILE):
        return
    uid = str(acc.get('uid') or '').strip()
    name = str(acc.get('_name') or acc.get('name') or '').strip()
    try:
        with open(LOCAL_ACCOUNTS_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        items = data if isinstance(data, list) else [data]
        for a in items:
            if not isinstance(a, dict):
                continue
            fuid = str(a.get('uid') or '').strip()
            fname = str(a.get('name') or '').strip()
            if not ((uid and fuid == uid) or (name and fname == name)):
                continue
            if a.get('accessToken') == acc['accessToken'] and a.get('refreshToken') == acc.get('refreshToken'):
                return
            a['accessToken'] = acc['accessToken']
            if acc.get('refreshToken'):
                a['refreshToken'] = acc['refreshToken']
            tmp = LOCAL_ACCOUNTS_FILE + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, LOCAL_ACCOUNTS_FILE)
            print('💾 [持久化] 已回写 !trae.json（%s）' % (fname or fuid or '账号'))
            return
    except Exception as e:
        print('⚠️ [持久化] !trae.json 回写失败: %s' % e)


def persist_tokens(acc):
    persist_local_json(acc)
    uid = str(acc.get('uid', '') or '').strip()
    if not uid:
        return
    files = []
    for d in [os.getenv('TRAE_ACCOUNT_DIR', '').strip(), HERE]:
        if d and os.path.isdir(d):
            files += glob.glob(os.path.join(d, 'trae-%s*.json' % uid))
    if not files:
        return
    fp = files[0]
    try:
        with open(fp, 'r', encoding='utf-8') as fh:
            d = json.load(fh)
        node = d['auth'] if 'auth' in d else d
        node['accessToken'] = acc['accessToken']
        node['refreshToken'] = acc.get('refreshToken', '')
        with open(fp, 'w', encoding='utf-8') as fh:
            json.dump(d, fh, ensure_ascii=False, indent=2)
        print('💾 [持久化] 已更新 %s' % os.path.basename(fp))
    except Exception as e:
        print('⚠️ [持久化] 写回失败: %s' % e)


# ══════════════════ 设备号 ══════════════════
def stable_device_id(seed):
    h = hashlib.sha256(seed.encode('utf-8')).digest()
    return str(int.from_bytes(h[:8], 'big') % (10 ** 16 - 10 ** 15) + 10 ** 15)


def load_device_ids():
    try:
        with open(DEVICE_ID_FILE, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_device_ids(ids):
    try:
        with open(DEVICE_ID_FILE, 'w', encoding='utf-8') as fh:
            json.dump(ids, fh, ensure_ascii=False, indent=2)
    except Exception as e:
        print('⚠️  [设备号] 持久化失败: %s' % e)


def real_device_ids():
    out = []
    paths = []
    env = os.getenv('TRAE_STORAGE_PATH', '').strip()
    if env:
        paths.append(env)
    found = find_storage_json()
    if found:
        paths.append(found)
    for p in paths:
        if not p or not os.path.isfile(p):
            continue
        try:
            with open(p, 'r', encoding='utf-8') as fh:
                storage = json.load(fh)
        except Exception:
            continue
        if not isinstance(storage, dict):
            continue
        d = dc_device_id(storage)
        if d and d not in out:
            out.append(d)
    return out


def rotate_device_id(acc):
    key = _acct_key(acc)
    name = acc.get('_name') or acc.get('name') or key
    tried = {str(acc.get('deviceId') or '').strip(), str(acc.get('_realDid') or '').strip()}
    for d in real_device_ids():
        if d not in tried:
            acc['deviceId'] = d
            acc['_realDid'] = d
            print('🔄 [设备号] %s 换用本机客户端的另一个真实设备号 %s' % (name, d))
            return d
    print('ℹ️  [设备号] %s 没有可切换的其它真实设备号（生成号注定 9074，不再更换）' % name)
    return None


def device_id_for(acc, manual=''):
    real = str(acc.get('_realDid') or '').strip()
    if is_valid_device_id(real):
        return real
    if is_valid_device_id(manual):
        return str(manual).strip()
    seed = _acct_key(acc)
    ids = load_device_ids()
    if seed in ids:
        return ids[seed]
    new_id = stable_device_id(seed)
    ids[seed] = new_id
    save_device_ids(ids)
    return new_id


# ══════════════════ 账号读取 ══════════════════
def parse_hours(spec):
    hours = set()
    for part in (spec or '').replace('，', ',').split(','):
        part = part.strip()
        if '-' in part:
            a, _, b = part.partition('-')
            if a.strip().isdigit() and b.strip().isdigit():
                hours |= {h % 24 for h in range(int(a), int(b) + 1)}
        elif part.isdigit():
            hours.add(int(part) % 24)
    return hours


def in_peak_hour(now=None):
    return (now or bj_now()).tm_hour in parse_hours(os.getenv('TRAE_PEAK_HOURS', '0'))


def pick_batch(pending):
    raw = os.getenv('TRAE_BATCH', '').strip().lower()
    if raw in ('all', '0', ''):
        return pending
    if pending and in_peak_hour():
        return pending
    try:
        size = max(1, int(raw))
    except Exception:
        size = 1
    start = bj_now().tm_hour % max(1, len(pending))
    return (pending[start:] + pending[:start])[:size]


def pick(d, *candidates):
    for c in candidates:
        if c in d and d[c]:
            return d[c]
    return ''


def normalize(d, src, name='', real=''):
    return {'accessToken': pick(d, 'accessToken', 'token', 'access_token'),
            'refreshToken': pick(d, 'refreshToken', 'refresh_token'),
            'deviceId': pick(d, 'deviceId', 'device_id'),
            'deviceKeyPem': pick(d, 'deviceKeyPem', 'device_key_pem'),
            'devicePubPem': pick(d, 'devicePubPem', 'device_pub_pem'),
            'machineId': pick(d, 'machineId', 'machine_id'),
            'uid': str(pick(d, 'uid', 'userId', 'user_id')),
            '_src': src, '_name': name, '_realDid': real}


def build_account(raw, name):
    if raw.get('accessToken'):
        return normalize(raw, 'accounts.json(明文token)', name or raw.get('uid', name),
                         str(raw.get('realDeviceId') or ''))
    if raw.get('icubeAuth'):
        return normalize(json.loads(decrypt_storage_value(raw['icubeAuth'].strip())),
                         'accounts.json(icubeAuth)', name)
    if raw.get('storagePath'):
        d, real = load_from_storage(raw['storagePath'])
        return normalize(d, raw['storagePath'], name, real)
    raise ValueError('账号 %s 缺少 accessToken / icubeAuth / storagePath' % (name or '(未命名)'))


def from_env_only():
    rts = []
    for i in range(1, 10):
        name = 'TRAE_REFRESH_TOKEN' if i == 1 else 'TRAE_REFRESH_TOKEN_%d' % i
        v = os.getenv(name, '').strip()
        if v:
            rts.append((i, v))
    if not rts or os.getenv('TRAE_ACCESS_TOKEN'):
        return []
    accs = []
    for i, rt in rts:
        idx = '' if i == 1 else '_%d' % i
        accs.append({'accessToken': os.getenv('TRAE_ACCESS_TOKEN%s' % idx, '').strip(),
                     'refreshToken': rt,
                     'deviceId': os.getenv('TRAE_DEVICE_ID%s' % idx, '').strip(),
                     'uid': os.getenv('TRAE_UID%s' % idx, '').strip(),
                     'name': os.getenv('TRAE_NAME%s' % idx, '') or '账号%d' % i})
    print('🔁 [兼容] 从 TRAE_REFRESH_TOKEN* 读到 %d 个账号，accessToken 将自动续期换取' % len(accs))
    return accs


def filter_only(accounts):
    only = os.getenv('TRAE_ONLY', '').strip()
    if not only:
        return accounts
    picked = [a for i, a in enumerate(accounts)
              if only in (str(i + 1), str(a.get('uid')), a.get('_name') or a.get('name') or '')]
    if picked:
        print('🎯 [筛选] TRAE_ONLY=%s -> 仅处理 %d 个账号' % (only, len(picked)))
        return picked
    print('⚠️ [筛选] TRAE_ONLY=%s 未匹配到账号，将处理全部' % only, file=sys.stderr)
    return accounts


def _load_local_json_accounts():
    """脚本同目录 !trae.json → 账号列表；文件不存在或不可用返回 None。"""
    if not os.path.isfile(LOCAL_ACCOUNTS_FILE):
        return None
    try:
        with open(LOCAL_ACCOUNTS_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except Exception as e:
        print('⚠️  [!trae.json] 读取失败: %s（回退环境变量）' % e, file=sys.stderr)
        return None
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        print('⚠️  [!trae.json] 结构不是数组（回退环境变量）', file=sys.stderr)
        return None
    accounts = []
    for i, raw in enumerate(data):
        if not isinstance(raw, dict):
            continue
        try:
            accounts.append(build_account(raw, raw.get('name') or raw.get('uid') or '账号%d' % (i + 1)))
        except Exception as e:
            print('❌ [!trae.json] 账号%d 加载失败: %s' % (i + 1, e), file=sys.stderr)
    if not accounts:
        print('⚠️  [!trae.json] 中无可用账号（回退环境变量）', file=sys.stderr)
        return None
    print('📁 [凭据] 检测到同目录 !trae.json，共 %d 个账号（已忽略环境变量账号配置）' % len(accounts))
    return accounts


def load_accounts():
    # 0) 优先：脚本同目录 !trae.json（存在即忽略环境变量账号配置）
    local = _load_local_json_accounts()
    if local is not None:
        return filter_only(apply_cache(local))

    # 1) 多账号：TRAE_ACCOUNTS 为 JSON 数组
    raw_list = os.getenv('TRAE_ACCOUNTS', '').strip()
    if raw_list:
        try:
            data = json.loads(raw_list)
        except Exception as e:
            print('❌ [凭据] TRAE_ACCOUNTS 不是合法 JSON: %s' % e, file=sys.stderr)
            print('   格式示例: [{"refreshToken":"AbCd...0000","uid":"账号1"}]', file=sys.stderr)
            print('   注意用英文双引号；推荐运行 trae_get_token.py --accounts 自动生成整行。', file=sys.stderr)
            sys.exit(1)
        data = [data] if isinstance(data, dict) else data
        accounts = []
        for i, raw in enumerate(data):
            try:
                accounts.append(build_account(raw, raw.get('name', '账号%d' % (i + 1))))
            except Exception as e:
                print('❌ [凭据] 账号%d 加载失败: %s' % (i + 1, e), file=sys.stderr)
        accounts = filter_only(apply_cache(accounts))
        if accounts:
            return accounts
        print('❌ [凭据] TRAE_ACCOUNTS 中没有任何可用账号。', file=sys.stderr)
        sys.exit(1)

    # 2) 兼容旧部署：TRAE_REFRESH_TOKEN[_N]
    accs = from_env_only()
    if accs:
        return filter_only(apply_cache(accs))

    # 3) 单账号：环境变量直给
    storage_path = os.getenv('TRAE_STORAGE_PATH', '').strip()
    if not storage_path:
        storage_path = find_storage_json() or ''
    if os.getenv('TRAE_ACCESS_TOKEN') or os.getenv('TRAE_ICUBE_AUTH') or storage_path:
        if os.getenv('TRAE_ICUBE_AUTH'):
            acc = normalize(json.loads(decrypt_storage_value(os.getenv('TRAE_ICUBE_AUTH').strip())),
                            '环境变量 TRAE_ICUBE_AUTH')
        elif storage_path:
            d, real = load_from_storage(storage_path)
            acc = normalize(d, storage_path, '', real)
        else:
            access_token = os.getenv('TRAE_ACCESS_TOKEN', '').strip()
            refresh_token = os.getenv('TRAE_REFRESH_TOKEN', '').strip()
            if access_token and refresh_token and access_token == refresh_token:
                print('❌ [凭据] TRAE_ACCESS_TOKEN 和 TRAE_REFRESH_TOKEN 不能填成同一个值：'\
                      'accessToken 是 eyJ 开头的长 JWT，refreshToken 形如 xxx=.18dxxx，两串完全不同。', file=sys.stderr)
                print('   单账号推荐只填 TRAE_REFRESH_TOKEN（脚本会自动换取 accessToken）；'\
                      '请用 trae_get_token.py 重新提取。', file=sys.stderr)
                sys.exit(1)
            if access_token and refresh_token and not access_token.startswith('eyJ') and refresh_token.startswith('eyJ'):
                print('❌ [凭据] 两个变量可能填反了：TRAE_ACCESS_TOKEN 应以 eyJ 开头，'\
                      '而 TRAE_REFRESH_TOKEN 不是。请把两串互换后重试。', file=sys.stderr)
                sys.exit(1)
            acc = {'accessToken': access_token,
                   'refreshToken': refresh_token,
                   'deviceId': os.getenv('TRAE_DEVICE_ID', ''),
                   'uid': os.getenv('TRAE_UID', ''),
                   'name': os.getenv('TRAE_NAME', '环境变量账号')}
        acc['deviceId'] = os.getenv('TRAE_DEVICE_ID', '')
        acc['_name'] = acc.get('name', '') or acc.get('uid', '')
        return [acc]

    print('❌ [凭据] 未找到账号配置。可选写法：脚本同目录 !trae.json / TRAE_ACCOUNTS(JSON数组，推荐) / '
          'TRAE_REFRESH_TOKEN(_2.._9) / TRAE_ACCESS_TOKEN+TRAE_REFRESH_TOKEN / '
          'TRAE_ICUBE_AUTH / TRAE_STORAGE_PATH', file=sys.stderr)
    sys.exit(1)


# ══════════════════ 签到接口 ══════════════════
def status_of(token, device_id):
    status, text = _post(EP_STATUS, ug_headers(token, device_id), REQ_BODY)
    try:
        d = json.loads(text)
    except Exception:
        return None, None, None, -1, text
    code = d.get('code', -1)
    if status >= 400:
        return None, None, None, code, text
    return (bool(d.get('checked_in', False)), d.get('credits', 0), d.get('enable', False), code, text)


def claim(token, device_id):
    status, text = _post(EP_CLAIM, ug_headers(token, device_id), REQ_BODY)
    try:
        body = json.loads(text)
    except Exception:
        return status, '?', text, None
    points = ((body.get('data') or {}).get('points')) if isinstance(body.get('data'), dict) else None
    return status, body.get('code', -1), body.get('message') or text[:120], points


def is_rate(code, status):
    return code == RATE_CODE or status in RATE_HTTP_CODES


def claim_with_retry(acc, cache):
    try:
        tries = max(1, int(os.getenv('CLAIM_TRIES', '1')))
    except Exception:
        tries = 1
    last = ('?', '')
    for attempt in range(1, tries + 1):
        status, code, msg, points = claim(acc['accessToken'], acc.get('deviceId'))
        last = (code, msg)
        if code == 0:
            return True, code, msg, points
        if code == ALREADY_CODE:
            return False, code, msg, None
        if code in AUTH_FAIL_CODES and acc.get('refreshToken'):
            print('🔑 [claim] 检测到 code=%s，尝试刷新 token ...' % code)
            ok, rmsg = ensure_token(acc, cache)
            if not ok:
                return False, code, rmsg, None
            continue
        if not is_rate(code, status):
            return False, code, msg
        if attempt < tries:
            wait = random.randint(4, 9)
            print('⏳ [限流] 第%d次被限，%ds 后重试（或交给下轮 cron）...' % (attempt, wait))
            time.sleep(wait)
            continue
        print('⏳ [限流] 本轮放弃，等下轮 cron 自动补签')
    return False, last[0], last[1], None


def credits_summary(acc):
    status, text = _post(EP_ENTITLE, ug_headers(acc['accessToken'], acc.get('deviceId')),
                         '{"require_usage": true}', 15)
    try:
        d = json.loads(text)
    except Exception:
        return None
    root = d.get('data') or d
    us = root.get('usage_summary') or {}
    try:
        total_amount, consumed = float(us.get('total_amount') or 0), float(us.get('consumed_amount') or 0)
        if total_amount > 0:
            return total_amount - consumed
    except Exception:
        pass
    try:
        packs = root.get('user_entitlement_pack_list') or []
        total, found = 0, False
        for p in packs:
            limit = ((p.get('entitlement_base_info') or {}).get('quota') or {}).get('credits_limit') or 0
            used = (p.get('usage') or {}).get('credits_amount') or 0
            if limit > 0:
                found = True
                total += max(limit - used, 0)
        return total if found else None
    except Exception:
        return None


# ══════════════════ 推送 ══════════════════
def notify_key():
    return QYWX_TOKEN.split('key=')[-1].strip()


def notify(text, title=''):
    key = notify_key()
    if not key:
        return False
    try:
        body = ('%s\n%s' % (title, text)) if title else text
        raw = body.encode('utf-8')
        if len(raw) > 2000:
            body = raw[:2000].decode('utf-8', 'ignore')
        req = urllib.request.Request(QYWX_URL + key,
                                    data=json.dumps({'msgtype': 'text',
                                                     'text': {'content': body}}).encode('utf-8'),
                                    headers={'Content-Type': 'application/json'})
        res = json.loads(urllib.request.urlopen(req, timeout=10).read().decode('utf-8'))
        ok = res.get('errcode') == 0
        print('%s [企业微信] 推送%s errcode=%s' % ('✅' if ok else '❌', '成功' if ok else '失败', res.get('errcode')))
        return ok
    except Exception as e:
        print('❌ [企业微信] 推送异常: %s' % e)
        return False


def notify_pushplus(title, content):
    if not PLUSPLUS_TOKEN:
        return
    try:
        req = urllib.request.Request(PUSHPLUS_URL,
                                    data=json.dumps({'token': PLUSPLUS_TOKEN, 'title': title,
                                                     'content': content, 'template': 'txt'}).encode('utf-8'),
                                    headers={'Content-Type': 'application/json'}, method='POST')
        urllib.request.urlopen(req, timeout=10)
        print('✅ [PushPlus] 推送成功')
    except Exception as e:
        print('❌ [PushPlus] 推送失败: %s' % e)


def push(title, text):
    notify(text, title)
    notify_pushplus(title, text)


# ══════════════════ 单个账号处理 ══════════════════
def checkin_account(acc, cache):
    name = acc.get('_name') or acc.get('name') or acc.get('uid') or '(未知)'
    result = {'name': name, 'uid': acc.get('uid', '-'), 'icon': '✅',
              'status': '失败', 'credits': '-', 'detail': '', '_claimed': False}

    if not acc.get('accessToken'):
        ok, msg = ensure_token(acc, cache) if acc.get('refreshToken') else (False, '解密后无 token')
        if not ok:
            result['status'] = 'token失效' if acc.get('refreshToken') else '无token'
            result['detail'] = msg
            return result

    acc['deviceId'] = device_id_for(acc, acc.get('deviceId', ''))
    print('📱 [设备号] %s: %s' % (name, acc['deviceId']))
    log_head('📡 %s 签到状态查询' % name)

    checked_in, credits, enable, code, raw = status_of(acc['accessToken'], acc['deviceId'])
    if code in AUTH_FAIL_CODES and acc.get('refreshToken'):
        print('🔑 [刷新] 检测到 code=%s 鉴权失败，尝试刷新 token ...' % code)
        ok, msg = ensure_token(acc, cache)
        if ok:
            print('✅ [刷新] token 已更新')
            checked_in, credits, enable, code, raw = status_of(acc['accessToken'], acc['deviceId'])
        else:
            print('❌ [刷新] 失败: %s' % msg)
    print('📊 [状态] 今日已签: %s   积分: %s   开放: %s' % (checked_in, credits, enable))

    if checked_in:
        pts = credits_summary(acc)
        result['icon'] = '☑️'
        result['status'] = '已签到'
        result['credits'] = pts if pts is not None else credits
        result['detail'] = ('今日已签，积分余额 %s' % _fmt(result['credits'])) if pts is not None \
            else '今日已签，积分 %s' % credits
        print('☑️  [结果] 今日已签到')
        return result
    if code in AUTH_FAIL_CODES:
        result['icon'] = '🔑'
        result['status'] = '鉴权失败'
        result['detail'] = 'token 无效且自动续期失败，需重新登录取新 refreshToken'
        print('❌ [结果] 鉴权失败（硬失败）')
        return result
    if checked_in is None:
        result['icon'] = '⏳'
        result['status'] = '待重试'
        result['detail'] = '状态查询未成功，本轮不发起 claim：%s' % (raw or '')[:70]
        print('⏳ [结果] 状态不可用，跳过 claim')
        return result
    if enable is False:
        result['icon'] = '🚫'
        result['status'] = '未开放'
        result['detail'] = '该账号未开放签到（enable=false），不再重复请求'
        print('🚫 [结果] 未开放签到')
        mark_done(_acct_key(acc), {'status': '未开放', 'credits': '-', 'at': bj()})
        return result

    result['_claimed'] = True
    ok, code, msg, gained = claim_with_retry(acc, cache)
    if code == RATE_CODE and os.getenv('TRAE_ROTATE', '1').strip() != '0':
        if rotate_device_id(acc):
            ok, code, msg, gained = claim_with_retry(acc, cache)
    if code == RATE_CODE:
        set_cooldown(_acct_key(acc), cooldown_minutes())
    if ok:
        confirmed = False
        if os.getenv('TRAE_VERIFY_CLAIM', '1').strip() != '0':
            checked_after, _, _, code_after, _ = status_of(acc['accessToken'], acc['deviceId'])
            confirmed = checked_after is True
            if not confirmed:
                result['icon'] = '⏳'
                result['status'] = '待确认'
                result['credits'] = credits if credits is not None else '-'
                result['detail'] = ('领取接口返回成功，但同设备号回查未确认（已签=%s，查询码=%s）——'
                                    '本轮不判定签到成功，下轮自动重试') % (checked_after, code_after)
                set_cooldown(_acct_key(acc), cooldown_minutes())
                print('⏳ [结果] 未确认到账，转下轮')
                return result
        pts = credits_summary(acc)
        result['status'] = '签到成功'
        gain = ('，本次 +%s 积分' % _fmt(gained)) if gained else ''
        if pts is not None:
            result['credits'] = pts
            result['detail'] = '签到成功%s，当前余额 %s' % (gain, _fmt(pts))
        else:
            _, credits_after, _, _, _ = status_of(acc['accessToken'], acc['deviceId'])
            result['credits'] = credits_after if credits_after is not None else credits
            result['detail'] = '签到成功（已回查确认），积分 %s → %s' % (credits, _fmt(result['credits']))
        print('🎉 [结果] 签到成功（已回查确认）')
    elif code == ALREADY_CODE:
        result['icon'] = '☑️'
        result['status'] = '已签到'
        result['credits'] = credits
        result['detail'] = '今日已签到(9095)'
        print('☑️  [结果] 今日已签到')
    elif code == RATE_CODE:
        result['icon'] = '⏳'
        result['status'] = '待重试'
        result['detail'] = '参与用户太多(9074)，本轮未签成，下轮 cron 自动补签'
        print('⏳ [结果] %s' % result['detail'])
    else:
        result['icon'] = '❌'
        result['status'] = '失败'
        result['detail'] = 'code=%s: %s' % (code, msg)
        print('❌ [结果] 签到失败: %s' % msg)
    return result


def _fmt(v):
    try:
        return '{:,.2f}'.format(float(v))
    except Exception:
        return str(v)


# ══════════════════ 主流程 ══════════════════
SOFT = ('待重试',)
DEAD = ('未开放', '鉴权失败')
COOLDOWN_MIN = 55
PEAK_COOLDOWN_MIN = 12
GAP_MIN, GAP_MAX = 12, 25


def main():
    accounts = load_accounts()
    cache = load_cache()
    log_title(len(accounts))

    results, pending = [], []
    state = load_state()
    for acc in accounts:
        key = _acct_key(acc)
        rec = (state.get('done') or {}).get(key)
        if rec:
            results.append({'name': acc.get('_name') or acc.get('name') or key,
                            'uid': acc.get('uid', '-'), 'icon': '☑️', 'status': '已签到',
                            'credits': rec.get('credits', '-'),
                            'detail': '今日已完成（%s），跳过请求' % rec.get('at', '-')})
            print('☑️  [%s] 今日已签到，跳过' % (acc.get('_name') or acc.get('name') or key))
        else:
            left = cooldown_left(key)
            if left > 0:
                print('⏳ [冷却] %s 9074 冷却中，还剩 %d 分钟，本轮跳过'
                      % (acc.get('_name') or acc.get('name') or key, (left + 59) // 60))
            else:
                pending.append(acc)
    if not pending:
        if any(cooldown_left(_acct_key(a)) > 0 for a in accounts):
            print('⏳ 全部待签账号都在冷却中，等冷却到点由 cron 补签')
        else:
            print('✅ 全部账号今日均已完成，无需请求接口')

    batch = pick_batch(pending)
    if len(batch) < len(pending):
        names = '、'.join(a.get('_name') or a.get('name') or _acct_key(a) for a in batch)
        print('🎚  [轮签] 本轮只签 %s（其余交给后续 cron，避开整点排队限流）' % names)
    if batch and os.getenv('TRAE_JITTER', '1').strip() != '0':
        wait = random.randint(0,1)
        print('🎲 [错峰] 随机等待 %d 秒再请求…' % wait)
        time.sleep(wait)

    prev_claimed = False
    for idx, acc in enumerate(batch):
        if idx > 0 and prev_claimed:
            gap = random.randint(GAP_MIN, GAP_MAX)
            print('\n⏳ [间隔] 等待 %d 秒后处理下一个账号...' % gap)
            time.sleep(gap)
        try:
            r = checkin_account(acc, cache)
            if r['status'] == '待重试':
                results.append(r)
                if os.getenv('TRAE_CIRCUIT', '0').strip() == '1':
                    rest = len(batch) - idx - 1
                    if rest > 0:
                        print('⏭  [熔断] 命中限流，跳过剩余 %d 个账号，等下一轮 cron' % rest)
                    break
                prev_claimed = True
                continue
            if r['status'] in ('签到成功', '已签到'):
                mark_done(_acct_key(acc), {'status': r['status'], 'credits': r.get('credits'),
                                           'at': bj()})
            prev_claimed = bool(r.get('_claimed'))
            results.append(r)
        except Exception as e:
            prev_claimed = False
            results.append({'name': acc.get('_name', '?'), 'uid': acc.get('uid', '-'),
                            'icon': '❌', 'status': '异常', 'credits': '-', 'detail': str(e)})

    ok_n = sum(1 for r in results if r['status'] == '签到成功')
    already_n = sum(1 for r in results if r['status'] == '已签到')
    soft_n = sum(1 for r in results if r['status'] in SOFT)
    dead_n = sum(1 for r in results if r['status'] in DEAD)
    fail_n = len(results) - ok_n - already_n - soft_n - dead_n

    log_box(['✅ 成功 %d  ☑️ 已签 %d  ⏳ 待重试 %d  ❌ 失败 %d' % (ok_n, already_n, soft_n, fail_n + dead_n),
             '🕒 结束时间: %s' % bj()], '🏁 Trae SOLO 签到完成')

    out = ['🕒 时间：%s' % bj(),
           '✅ 成功 %d  ☑️ 已签 %d  ⏳ 待重试 %d  ❌ 失败 %d' % (ok_n, already_n, soft_n, fail_n + dead_n)]
    for r in results:
        out.append('%s %s(%s): %s | %s' % (r['icon'], r['name'], r['uid'], r['status'], r['detail']))
    push('🤖 Trae SOLO 多账号签到', '\n'.join(out))


if __name__ == '__main__':
    main()