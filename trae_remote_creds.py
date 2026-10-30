#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trae 远端凭据抓取 · trae_remote_creds.py
────────────────────────────────────────────────────────────
用途：当某台已登录 Trae 的机器不在本机（例如 MQTT 远端主机），
本脚本通过 MQTT RPC 读取那台机器的 storage.json，在本地解密出
accessToken / refreshToken / 设备私钥，并合并写回同目录 !trae.json。

为什么需要设备私钥：
  Trae 新版 ExchangeToken 会校验 DeviceProof。只拿 refreshToken、没有
  签发它的那台机器的私钥时，服务端会返回
      http=400 code=10101 refresh token is not matched to the client
  即使 refreshToken 本身仍然有效。补上 deviceKeyPem / devicePubPem /
  deviceId 后再续期就能通过；本脚本会把这三样一起取回来。

隐私约定：
  MQTT 主机名、request_topic、私钥表达式等全部保存在 !trae.json 的
  mqtt 字段里，不写进代码。私钥日志只显示前缀与 sha256 指纹。

使用：
  python trae_remote_creds.py                 # 抓取配置里所有带 mqtt 的账号
  python trae_remote_creds.py --host mqtt:lenovo  # 只抓指定 MQTT 通道（可重复/逗号分隔）
  python trae_remote_creds.py --host local    # 只处理本机抓取的账号
  python trae_remote_creds.py --dry-run       # 只解析、不写文件
  python trae_remote_creds.py --verify        # 写完立即查一次积分接口
  python trae_remote_creds.py --refresh       # 强制用设备证明续期一次（会轮换 RT）
  python trae_remote_creds.py --list          # 查看配置里的主机/账号对应关系
  python trae_remote_creds.py --userinfo      # 只补全 remark（掩码手机号/注册时间等）

字段说明：
  - 顶层只保留脚本真正要用的字段：accessToken / refreshToken / uid / deviceId /
    deviceKeyPem / devicePubPem / machineId / host（和可选的 mqtt 配置）。
  - host 是“用哪条通道抓这份凭据”的功能键，值只有两种写法：
      local            本机 storage.json
      mqtt:<topic>     走 MQTT 通道，topic 即 mqtt.requestTopic（如 mqtt:lenovo）
    抓取、--host 过滤、账号匹配都靠它；--host 接受同样的写法（裸 topic 会自动补 mqtt:）。
  - hostName（远端机器名）、sourceStorage（storage.json 路径）、fetchedAt（最近抓取
    时间）、tokenExpiresAt（token 过期时间）只是给人看的，全部放在 remark。
  - 不再有 credentialSource：local / mqtt 已由 host 表达，属冗余字段，迁移时直接丢弃。
  - 每个账号的 "remark" 是自由注释区，所有脚本都不读取、不影响运行；可以放
    name / phoneMasked / 备注 / 归属人 / tags 等任意信息，后续新字段也不会破坏凭据逻辑。
  - remark 里的时间统一为北京时间 YYYY-MM-DD HH:MM:SS（ISO8601 会自动转换）。

!trae.json 中远端账号示例（密钥只放这里，不要写进代码）：
  {
    "uid": "<远端账号 uid>",
    "deviceId": "<设备号>",
    "host": "mqtt:<topic>",
    "remark": {
      "name": "<账号显示名>",
      "hostName": "<远端机器名>",
      "sourceStorage": "<远端 storage.json 路径>",
      "fetchedAt": "2026-10-30 11:06:55",
      "tokenExpiresAt": "2026-11-13 11:06:55",
      "phoneMasked": "175******96",
      "registerTime": "2025-07-27 23:51:40"
    },
    "mqtt": {
      "requestTopic": "<下发 topic>",
      "privateKey": "<私钥或整数表达式>",
      "minBrokerCount": 6,
      "timeout": 20,
      "repoPath": "<multi_mqtt 仓库路径>"
    }
  }

实测结论（补充说明）：
  - code=10101 不等于 refreshToken 过期。补上签发机器的 DeviceProof 后，
    旧 refreshToken 仍能续期，并返回当前链头的新 refreshToken；服务端会按
    “设备 + 祖先 token”映射到最新链。
  - 真正的失败原因是：没有设备私钥时走了无证明的 cloudide 客户端路径，
    与 IDE 客户端签发的 refreshToken 不匹配，于是报 10101。
  - trae_checkin.py 只会用 exchange 接口轮换 token，不会重新登录；设备密钥
    缺失/用错机器时它同样救不回来。把设备私钥写进 !trae.json 后即可正常续期。
"""

import argparse, base64, hashlib, json, os, platform, re, sys, time
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(HERE, '!trae.json')
LOG_FILE = os.path.join(HERE, '.trae_remote_fetch.log')
UG_HOST = 'https://api.trae.cn'
EP_ENTITLE = UG_HOST + '/trae/api/v2/pay/user_current_entitlement_list'
EP_USERINFO = UG_HOST + '/cloudide/api/v3/trae/GetUserInfo'
AUTH_FAIL_CODES = (1001, 1002)

# ══════════════════ 日志 ══════════════════
_LOG_PATH = ''


def bj_now():
    return datetime.now(timezone.utc) + timedelta(hours=8)


def log(msg, quiet=False):
    line = '%s %s' % (bj_now().strftime('%H:%M:%S'), msg)
    if not quiet:
        print(line, flush=True)
    if _LOG_PATH:
        try:
            with open(_LOG_PATH, 'a', encoding='utf-8') as fh:
                fh.write('%s %s\n' % (bj_now().strftime('%Y-%m-%d %H:%M:%S'), msg))
        except Exception:
            pass


def fp(s):
    """敏感串的短指纹：只用于日志里核对是不是同一条，不泄露原文。"""
    return hashlib.sha256((s or '').encode('utf-8')).hexdigest()[:10] if s else '-'


def mask_key(v):
    s = str(v or '')
    if not s:
        return '(空)'
    return '%s…(len=%d, sha256=%s)' % (s[:4], len(s), fp(s))


def acct_name(a, fallback=''):
    """统一展示名：remark.name；没有就显示 {uid:数字}。"""
    rem = a.get('remark') if isinstance(a.get('remark'), dict) else {}
    n = str(rem.get('name') or '').strip()
    if n:
        return n
    uid = str(a.get('uid') or '').strip()
    if uid:
        return '{uid:%s}' % uid
    return fallback or '账号'


# ══════════════════ JWT ══════════════════
def jwt_payload(token):
    try:
        p = token.split('.')[1]
        return json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))
    except Exception:
        return {}


def jwt_uid(token):
    return str(jwt_payload(token).get('data', {}).get('id', ''))


def jwt_exp(token):
    return int(jwt_payload(token).get('exp', 0) or 0)


def fmt_ts(sec):
    if not sec:
        return '-'
    return (datetime.fromtimestamp(int(sec), timezone.utc) + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')


def fmt_iso(v):
    """ISO8601（如 2025-07-27T23:51:40.348+08:00）→ 北京时间 YYYY-MM-DD HH:MM:SS。"""
    s = str(v or '').strip()
    if not s:
        return ''
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00').replace('z', '+00:00'))
    except Exception:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt.astimezone(timezone.utc) + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')


def fmt_when(v):
    """时间值统一成可读北京时间：秒级时间戳 / 数字字符串 / ISO8601 / 已是可读格式。"""
    if isinstance(v, (int, float)) and v > 0:
        return fmt_ts(v)
    s = str(v or '').strip()
    if not s:
        return ''
    if s.isdigit():
        return fmt_ts(int(s))
    if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$', s):
        return s
    return fmt_iso(s)


def rem_of(a):
    """取账号的 remark 注释区，保证是 dict。"""
    rem = a.get('remark')
    if not isinstance(rem, dict):
        rem = {}
        a['remark'] = rem
    return rem


def rem_time(a, key):
    """remark 优先、兼容旧的顶层字段，供日志/--list 展示。"""
    return (a.get('remark') or {}).get(key) or a.get(key) or '-'


def canon_host(v):
    """规范化 host：local 原样保留；其余一律写成 mqtt:<topic>（裸 topic 自动补前缀）。"""
    s = str(v or '').strip()
    if not s:
        return ''
    if s == 'local' or s.startswith('mqtt:'):
        return s
    return 'mqtt:%s' % s


# ══════════════════ storage.json 解密（纯标准库 AES-128-CBC） ══════════════════
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
ENC_AES = bytes([0x74, 0x63, 0x05, 0x10, 0x00, 0x00])
ENC_AES_PRIVATE = bytes([18, 57, 32, 32, 2, 3])


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _build_sbox():
    inv = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            if _gmul(i, j) == 1:
                inv[i] = j
                break
    sb = [0] * 256
    for i in range(256):
        x = inv[i] if i else 0
        s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sb[i] = s ^ 0x63
    return sb


SBOX = _build_sbox()
INV = [0] * 256
for _i, _v in enumerate(SBOX):
    INV[_v] = _i
RC = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand(key):
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RC[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return w


def _rk(w, r):
    ws = w[r * 4:r * 4 + 4]
    return [ws[c][k] for c in range(4) for k in range(4)]


def _addrk(s, k):
    return [s[i] ^ k[i] for i in range(16)]


def _isub(s):
    return [INV[b] for b in s]


def _ishift(s):
    return [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11], s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]]


def _imix(s):
    o = []
    for c in range(4):
        a = s[c * 4:c * 4 + 4]
        o += [_gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9),
              _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13),
              _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11),
              _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)]
    return o


def aes128_cbc_decrypt(key, iv, data):
    w = _expand(key)
    out = b''
    prev = list(iv)
    for off in range(0, len(data), 16):
        blk = list(data[off:off + 16])
        s = _addrk(blk, _rk(w, 10))
        for r in range(9, 0, -1):
            s = _ishift(s)
            s = _isub(s)
            s = _addrk(s, _rk(w, r))
            s = _imix(s)
        s = _ishift(s)
        s = _isub(s)
        s = _addrk(s, _rk(w, 0))
        out += bytes(a ^ b for a, b in zip(s, prev))
        prev = blk
    return out


def dec_type(header):
    if header[0:6] == ENC_AES:
        return 'AES'
    if header[0:6] == ENC_AES_PRIVATE:
        return 'AES_PRIVATE'
    return 'UNKNOWN'


def dec_storage(b64):
    """解密 storage.json 里 iCubeAuthInfo://... 的 Base64 值，带 SHA-512 校验。"""
    buf = base64.b64decode(b64)
    if len(buf) < 38:
        raise ValueError('密文长度不足')
    et = dec_type(buf[0:6])
    if et == 'UNKNOWN':
        raise ValueError('未知加密头: %s' % buf[0:6].hex())
    salt = SALT_AES_PRIVATE if et == 'AES_PRIVATE' else SALT_AES
    fh = hashlib.sha512(hashlib.sha512(buf[6:38]).digest() + salt).digest()
    pt = aes128_cbc_decrypt(fh[:16], fh[16:32], buf[38:])
    stored_hash, plain = pt[:64], pt[64:]
    pad = plain[-1] if plain else 0
    plain = plain[:-pad] if 1 <= pad <= 16 else plain.rstrip(b'\x00').rstrip()
    if stored_hash != hashlib.sha512(plain).digest():
        raise ValueError('SHA-512 校验失败，解密密钥不对')
    return plain.decode('utf-8'), et


# ══════════════════ 远端读取代码 ══════════════════
def remote_code(storage_path=''):
    """在远端 Python 服务进程里执行：找到 Trae storage.json，回传两个加密块。"""
    override = json.dumps(storage_path or '', ensure_ascii=False)
    return r'''
import os, json, platform
OVERRIDE = %s
home = os.path.expanduser("~")
names = ("Trae CN", "TRAE SOLO CN", "TRAE SOLO", "Trae", ".trae-cn", ".trae")
cands = []
if OVERRIDE:
    cands.append(OVERRIDE)
ad = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
for n in names:
    cands.append(os.path.join(ad, n, "User", "globalStorage", "storage.json"))
    cands.append(os.path.join(home, ".config", n, "User", "globalStorage", "storage.json"))
    cands.append(os.path.join(home, "Library", "Application Support", n, "User", "globalStorage", "storage.json"))
found = None
for p in cands:
    if p and os.path.isfile(p):
        found = p
        break
if not found:
    print(json.dumps({"ok": False, "error": "远端找不到 storage.json", "tried": cands}, ensure_ascii=False))
else:
    s = json.load(open(found, encoding="utf-8"))
    did = ""
    for k in s:
        if k.startswith("iCubeAuthInfo://icube-dc:"):
            d = k.split(":")[-1].strip()
            if d.isdigit():
                did = d
                break
    out = {"ok": True, "storage": found, "did": did,
           "machineId": (s.get("telemetry.machineId") or "").strip(),
           "cloudide": s.get("iCubeAuthInfo://icube.cloudide") or "",
           "device": s.get("iCubeAuthInfo://icube-dc:" + did) if did else "",
           "host": platform.node(), "os": platform.system(), "osver": platform.release(),
           "mtime": int(os.stat(found).st_mtime)}
    print(json.dumps(out, ensure_ascii=False))
''' % override


def rpc_fetch(host_cfg, storage_path=''):
    repo = (host_cfg.get('repoPath') or os.environ.get('TRAE_MQTT_REPO') or '').strip()
    if repo and os.path.isdir(repo) and repo not in sys.path:
        sys.path.insert(0, repo)
    try:
        from client import client_mqtt
    except Exception as e:
        raise RuntimeError('导入 client_mqtt 失败（检查 mqtt.repoPath）: %s' % e)
    topic = str(host_cfg.get('requestTopic') or '').strip()
    key = host_cfg.get('privateKey')
    if not topic or not key:
        raise RuntimeError('mqtt.requestTopic / mqtt.privateKey 未配置')
    timeout = float(host_cfg.get('timeout') or 20)
    mb = int(host_cfg.get('minBrokerCount') or 6)
    reply = str(host_cfg.get('replyTopic') or '').strip()
    kw = {}
    if reply:
        kw['reply_topic'] = reply
    log('  → MQTT RPC: topic=%s key=%s mb=%d timeout=%.0fs' % (topic, mask_key(key), mb, timeout))
    t0 = time.time()
    res = client_mqtt.rpc(remote_code(storage_path), request_topic=topic, timeout=timeout,
                          k=key, mb=mb, **kw)
    cost = (time.time() - t0) * 1000
    log('  ← RPC 返回: ok=%s latency_ms=%s wall_ms=%.0f broker=%s server_time=%s'
        % (res.get('ok'), res.get('latency_ms'), cost, res.get('server_from'), res.get('server_time')))
    if not res.get('ok'):
        raise RuntimeError('RPC 执行失败: %s' % (res.get('stdout') or res)[:300])
    raw = (res.get('stdout') or '').strip()
    lines = [x for x in raw.splitlines() if x.strip()]
    if not lines:
        raise RuntimeError('远端没有输出')
    try:
        data = json.loads(lines[-1])
    except Exception:
        raise RuntimeError('远端输出不是 JSON: %s' % raw[:200])
    if not data.get('ok'):
        raise RuntimeError('远端读取失败: %s' % data.get('error'))
    data['_rpc'] = {'req_id': res.get('req_id'), 'latency_ms': res.get('latency_ms'),
                    'broker': res.get('client_from'), 'reply_from': res.get('server_from')}
    return data


# ══════════════════ 本机读取（不联网） ══════════════════
def local_storage_path(override=''):
    home = os.path.expanduser('~')
    names = ('Trae CN', 'TRAE SOLO CN', 'TRAE SOLO', 'Trae', '.trae-cn', '.trae')
    ad = os.environ.get('APPDATA') or os.path.join(home, 'AppData', 'Roaming')
    cands = [override] if override else []
    for n in names:
        cands.append(os.path.join(ad, n, 'User', 'globalStorage', 'storage.json'))
        cands.append(os.path.join(home, '.config', n, 'User', 'globalStorage', 'storage.json'))
        cands.append(os.path.join(home, 'Library', 'Application Support', n, 'User', 'globalStorage', 'storage.json'))
    for p in cands:
        if p and os.path.isfile(p):
            return p
    return ''


def local_blob(override=''):
    """读取本机 storage.json，返回与远端 RPC 相同结构的字典。"""
    p = local_storage_path(override)
    if not p:
        raise RuntimeError('本机找不到 Trae storage.json（Trae 未安装或未登录）')
    s = json.load(open(p, encoding='utf-8'))
    did = ''
    for k in s:
        if k.startswith('iCubeAuthInfo://icube-dc:'):
            d = k.split(':')[-1].strip()
            if d.isdigit():
                did = d
                break
    if not did:
        raise RuntimeError('%s 里没有设备号（iCubeAuthInfo://icube-dc:<数字>）' % p)
    return {'ok': True, 'storage': p, 'did': did,
            'machineId': (s.get('telemetry.machineId') or '').strip(),
            'cloudide': s.get('iCubeAuthInfo://icube.cloudide') or '',
            'device': s.get('iCubeAuthInfo://icube-dc:%s' % did) or '',
            'host': platform.node(), 'os': platform.system(), 'osver': platform.release(),
            'mtime': int(os.stat(p).st_mtime)}


# ══════════════════ 配置 ══════════════════
def migrate_account(a):
    """兼容旧格式并归一化账号字段：
      - name / screenName / sourceStorage / hostName / fetchedAt / tokenExpiresAt → remark
      - realDeviceId → deviceId
      - 丢弃冗余的 credentialSource（local / mqtt 已由 host 表达）
      - remark 内时间统一成可读的北京时间 YYYY-MM-DD HH:MM:SS
    """
    rem = rem_of(a)
    if rem.get('screenName') and not rem.get('name'):
        rem['name'] = rem.pop('screenName')
    rem.pop('screenName', None)
    if a.get('name') and not rem.get('name'):
        rem['name'] = a.pop('name')
    a.pop('name', None)
    if a.get('realDeviceId'):
        if not a.get('deviceId'):
            a['deviceId'] = a['realDeviceId']
        a.pop('realDeviceId')
    a.pop('credentialSource', None)
    if a.get('host'):
        a['host'] = canon_host(a['host'])
    for k in ('sourceStorage', 'hostName'):
        v = a.pop(k, None)
        if v:
            rem.setdefault(k, v)
    for k in ('fetchedAt', 'tokenExpiresAt'):
        v = a.pop(k, None)
        if v:
            rem[k] = fmt_when(v)
    for k in ('userInfoFetchedAt', 'registerTime', 'lastLoginTime'):
        if rem.get(k):
            rem[k] = fmt_when(rem[k])
    return a


def load_items(path):
    with open(path, 'r', encoding='utf-8') as fh:
        data = json.load(fh)
    items = data if isinstance(data, list) else [data]
    return [migrate_account(a) for a in items if isinstance(a, dict)]


def save_items(path, items):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(items, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def mqtt_hosts(items):
    """把配置里出现过的 MQTT 主机去重成 {host: 第一个 mqtt 配置}。"""
    hosts = {}
    for a in items:
        cfg = a.get('mqtt') or {}
        topic = canon_host(cfg.get('requestTopic') or a.get('host') or '')
        if cfg and topic and topic not in hosts:
            hosts[topic] = cfg
    return hosts


def find_account(items, uid, topic):
    for a in items:
        if uid and str(a.get('uid') or '').strip() == uid:
            return a
    # 远端 uid 与配置里的 uid 不一致时，退化为按 host 匹配占位账号
    for a in items:
        cfg = a.get('mqtt') or {}
        if canon_host(cfg.get('requestTopic') or a.get('host') or '') == canon_host(topic):
            return a
    return None


# ══════════════════ 合并 ══════════════════
def merge_account(item, remote, account_json, device_json, host_cfg, local=False):
    """把读取结果合并进配置项，返回变更字段列表。

    远端 Trae 客户端可能很久没开，它手里的 accessToken 可能比本地续期后的更旧；
    因此只有远端 token 更新时才覆盖本地 token，避免把本地刚轮换的新链写回旧链。
    """
    changes = []
    now = int(time.time())
    at = account_json.get('token') or account_json.get('accessToken') or ''
    rt = account_json.get('refreshToken') or ''
    uid = str(account_json.get('userId') or jwt_uid(at) or '').strip()
    rem = item.get('remark') if isinstance(item.get('remark'), dict) else {}
    name = ((account_json.get('account') or {}).get('username') or account_json.get('username')
            or rem.get('name') or '').strip()
    did = remote.get('did') or ''
    priv = (device_json.get('privateKeyPEM') or '').strip()
    pub = (device_json.get('publicKeyPEM') or '').strip()
    local_at = str(item.get('accessToken') or '').strip()
    local_exp, remote_exp = jwt_exp(local_at), jwt_exp(at)
    keep_local = bool(local_at) and local_exp >= remote_exp
    note = ('本地 token 不旧于远端（本地 exp %s ≥ 远端 %s），保留本地 token'
            % (fmt_ts(local_exp), fmt_ts(remote_exp))) if keep_local else ''
    at_use, rt_use = (local_at, str(item.get('refreshToken') or '').strip()) if keep_local else (at, rt)

    def put(k, v):
        if v and item.get(k) != v:
            item[k] = v
            changes.append(k)

    def put_rem(k, v):
        if v and rem.get(k) != v:
            rem[k] = v
            changes.append('remark.' + k)

    put('uid', uid)
    put_rem('name', name)
    if not keep_local:
        put('accessToken', at)
        put('refreshToken', rt)
    put('deviceId', did)
    put('deviceKeyPem', priv)
    put('devicePubPem', pub)
    put('machineId', (remote.get('machineId') or '').strip())
    put_rem('hostName', remote.get('host') or platform.node())
    put_rem('sourceStorage', remote.get('storage'))
    if local:
        put('host', 'local')
    else:
        put('host', canon_host((host_cfg or {}).get('requestTopic') or item.get('host') or ''))
        item.setdefault('mqtt', dict(host_cfg or {}))
    item['remark'] = rem
    put_rem('fetchedAt', fmt_ts(now))
    put_rem('tokenExpiresAt', fmt_ts(jwt_exp(at_use)))
    return changes, uid, at_use, rt_use, did, note


# ══════════════════ 验证 ══════════════════
def credits_check(token, device_id):
    import urllib.request
    body = json.dumps({'require_usage': True, 'full_data': True}).encode('utf-8')
    req = urllib.request.Request(EP_ENTITLE, data=body, method='POST', headers={
        'Authorization': 'Cloud-IDE-JWT ' + token, 'X-User-Region': 'cn',
        'x-device-id': device_id, 'Content-Type': 'application/json',
        'User-Agent': 'TraeRemoteCreds/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode('utf-8', 'replace')
            status = resp.status
    except Exception as e:
        return {'status': -1, 'error': str(e)}
    try:
        b = json.loads(text)
    except Exception:
        return {'status': status, 'error': text[:200]}
    s = b.get('usage_summary') or {}
    total, used = s.get('total_amount'), s.get('consumed_amount')
    return {'status': status, 'code': b.get('code', -1), 'total': total, 'used': used,
            'remain': round(total - used, 2) if (total is not None and used is not None) else None,
            'auth_fail': b.get('code') in AUTH_FAIL_CODES}


def fetch_userinfo(token):
    """调用 Trae 官方 GetUserInfo，拿掩码手机号/注册时间/最近登录方式。"""
    import urllib.request
    if not token:
        return None
    body = json.dumps({'ReqSource': 'IDE', 'IDEVersion': '3.4.2'}).encode('utf-8')
    req = urllib.request.Request(EP_USERINFO, data=body, method='POST', headers={
        'Content-Type': 'application/json', 'x-cloudide-token': token,
        'User-Agent': 'TraeRemoteCreds/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8', 'replace'))
        return data.get('Result') or None
    except Exception:
        return None


def enrich_userinfo(item):
    """把账号资料写进自由注释区 remark；不覆盖用户自己写的 note。"""
    info = fetch_userinfo(str(item.get('accessToken') or '').strip())
    if not info:
        return False, 'GetUserInfo 无结果（token 过期或无权限）'
    remark = item.get('remark') if isinstance(item.get('remark'), dict) else {}
    fields = {
        'name': info.get('ScreenName') or '',
        'phoneMasked': info.get('NonPlainTextMobile') or '',
        'emailMasked': info.get('NonPlainTextEmail') or '',
        'lastLoginType': info.get('LastLoginType') or '',
        'registerTime': fmt_when(info.get('RegisterTime') or ''),
        'lastLoginTime': fmt_when(info.get('LastLoginTime') or ''),
        'region': info.get('Region') or '',
        'userInfoFetchedAt': fmt_ts(int(time.time())),
    }
    for k, v in fields.items():
        if v:
            remark[k] = v
    item['remark'] = remark
    return True, remark


def enrich_all(items, args):
    log('══ Trae 账号资料补全（GetUserInfo）══')
    ok = fail = 0
    for a in items:
        if not a.get('accessToken'):
            continue
        good, res = enrich_userinfo(a)
        if good:
            ok += 1
            log('  ✅ %s uid=%s 手机掩码=%s 注册=%s'
                % (acct_name(a), a.get('uid') or '-',
                   res.get('phoneMasked') or '-', res.get('registerTime') or '-'))
        else:
            fail += 1
            log('  ❌ %s uid=%s: %s' % (acct_name(a), a.get('uid') or '-', res))
    if not args.dry_run:
        save_items(args.config, items)
        log('已写回 %s' % args.config)
    else:
        log('--dry-run：未写文件')
    log('完成: 成功 %d，失败 %d' % (ok, fail))
    return 0 if fail == 0 else 1


def force_refresh(item):
    """用远端设备私钥做一次 DeviceProof 续期；成功则更新 access/refresh token。"""
    try:
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import trae_credit_monitor as mon
    except Exception as e:
        return None, '导入 trae_credit_monitor 失败: %s' % e
    keys = {'deviceId': str(item.get('deviceId') or ''),
            'privateKeyPem': item.get('deviceKeyPem') or '',
            'publicKeyPem': item.get('devicePubPem') or '',
            'machineId': item.get('machineId') or ''}
    if not (keys['deviceId'] and keys['privateKeyPem'] and keys['publicKeyPem']):
        return None, '缺少设备私钥，无法做 DeviceProof 续期'
    new_at, new_rt, msg = mon.refresh(item.get('refreshToken') or '', keys)
    if not new_at:
        return None, msg
    item['accessToken'] = new_at
    if new_rt:
        item['refreshToken'] = new_rt
    rem_of(item)['tokenExpiresAt'] = fmt_ts(jwt_exp(new_at))
    return (new_at, new_rt), 'ok'


# ══════════════════ 主流程 ══════════════════
def run_one(topic, host_cfg, items, args):
    log('─' * 58)
    log('▶ 目标通道: %s' % topic)
    storage_path = str(host_cfg.get('storagePath') or '').strip()
    log('① 远端定位 storage.json%s' % ('（使用配置路径）' if storage_path else '（自动探测 Trae CN / SOLO）'))
    remote = rpc_fetch(host_cfg, storage_path)
    log('② 远端环境: host=%s os=%s %s storage=%s mtime=%s'
        % (remote.get('host'), remote.get('os'), remote.get('osver'),
           remote.get('storage'), fmt_ts(remote.get('mtime'))))
    log('   设备号 did=%s machineId=%s' % (remote.get('did') or '-', (remote.get('machineId') or '-')[:16] + '…'))
    if not remote.get('cloudide') or not remote.get('device'):
        raise RuntimeError('远端 storage.json 缺少登录凭据（Trae 未登录？）')

    log('③ 本地解密凭据块（AES-128-CBC + SHA-512 校验）')
    acc_text, acc_type = dec_storage(remote['cloudide'])
    dev_text, dev_type = dec_storage(remote['device'])
    account_json, device_json = json.loads(acc_text), json.loads(dev_text)
    log('   cloudide=%s 元数据校验通过；device-key=%s 元数据校验通过' % (acc_type, dev_type))

    at = account_json.get('token') or account_json.get('accessToken') or ''
    rt = account_json.get('refreshToken') or ''
    uid = str(account_json.get('userId') or jwt_uid(at) or '')
    log('④ 解析 token: uid=%s accessToken=%s exp=%s(%s) refreshToken=%s'
        % (uid, fp(at), jwt_exp(at), fmt_ts(jwt_exp(at)), fp(rt)))
    log('   refreshExpiredAt=%s account=%s'
        % (account_json.get('refreshExpiredAt') or '-',
           (account_json.get('account') or {}).get('username') or '-'))
    if not at or not rt:
        raise RuntimeError('解密后 accessToken / refreshToken 为空')

    item = find_account(items, uid, topic)
    if item is None:
        if not args.add:
            raise RuntimeError('配置里没有 uid=%s；如确需接入请加 --add' % (uid or '(空)'))
        log('⑤ 配置中没有该账号，新增一条（--add）')
        item = {}
        items.append(item)
    else:
        log('⑤ 配置中命中账号: %s' % acct_name(item, '(空)'))
    changes, uid, at, rt, did, note = merge_account(item, remote, account_json, device_json, host_cfg)
    log('⑥ 合并字段: %s' % (', '.join(changes) if changes else '无变化（已是最新）'))
    if note:
        log('   ℹ️  %s' % note)
    if args.userinfo:
        good, res = enrich_userinfo(item)
        if good:
            log('   📇 remark 已补全: 手机掩码=%s 注册=%s 最近登录=%s(%s)'
                % (res.get('phoneMasked') or '-', res.get('registerTime') or '-',
                   res.get('lastLoginTime') or '-', res.get('lastLoginType') or '-'))
        else:
            log('   ⚠️  remark 补全失败: %s' % res)

    if args.refresh:
        log('⑦ 用设备私钥强制续期（ExchangeToken + DeviceProof）…')
        got, msg = force_refresh(item)
        if got:
            log('   ✅ 续期成功 accessToken=%s exp=%s(%s)'
                % (fp(item['accessToken']), jwt_exp(item['accessToken']), fmt_ts(jwt_exp(item['accessToken']))))
        else:
            log('   ❌ 续期失败: %s' % msg)
            if '10101' in msg or '20403' in msg or '20405' in msg:
                raise RuntimeError(msg)

    if not args.dry_run:
        save_items(args.config, items)
        log('⑧ 已写回 %s' % args.config)
    else:
        log('⑧ --dry-run：未写文件')

    if args.verify or args.refresh:
        c = credits_check(item.get('accessToken') or '', item.get('deviceId') or did)
        log('⑨ 积分接口验证: http=%s code=%s 已用=%s 剩余=%s'
            % (c.get('status'), c.get('code'), c.get('used'), c.get('remain')))
        if c.get('auth_fail') or c.get('status', 0) >= 400:
            raise RuntimeError('token 验证失败: %s' % c)
    return item


def run_local(items, args):
    """本机 Trae 已登录时，直接读 storage.json（零网络、零 MQTT）。"""
    log('─' * 58)
    log('▶ 本机 storage.json（不联网）')
    blob = local_blob(str(args.storage_path or ''))
    log('① 路径: %s（mtime=%s）' % (blob.get('storage'), fmt_ts(blob.get('mtime'))))
    log('② 本机环境: host=%s os=%s %s did=%s'
        % (blob.get('host'), blob.get('os'), blob.get('osver'), blob.get('did') or '-'))
    if not blob.get('cloudide') or not blob.get('device'):
        raise RuntimeError('本机 storage.json 缺少登录凭据（Trae 未登录？）')
    log('③ 本地解密凭据块（AES-128-CBC + SHA-512 校验）')
    acc_text, acc_type = dec_storage(blob['cloudide'])
    dev_text, dev_type = dec_storage(blob['device'])
    account_json, device_json = json.loads(acc_text), json.loads(dev_text)
    log('   cloudide=%s 元数据校验通过；device-key=%s 元数据校验通过' % (acc_type, dev_type))
    at = account_json.get('token') or account_json.get('accessToken') or ''
    rt = account_json.get('refreshToken') or ''
    uid = str(account_json.get('userId') or jwt_uid(at) or '')
    log('④ 解析 token: uid=%s accessToken=%s exp=%s(%s) refreshToken=%s'
        % (uid, fp(at), jwt_exp(at), fmt_ts(jwt_exp(at)), fp(rt)))
    item = find_account(items, uid, 'local')
    if item is None:
        if not args.add:
            raise RuntimeError('配置里没有 uid=%s；如确需接入请加 --add' % (uid or '(空)'))
        log('⑤ 配置中没有该账号，新增一条（--add）')
        item = {}
        items.append(item)
    else:
        log('⑤ 配置中命中账号: %s' % acct_name(item, '(空)'))
    changes, uid, at, rt, did, note = merge_account(item, blob, account_json, device_json, None, local=True)
    log('⑥ 合并字段: %s' % (', '.join(changes) if changes else '无变化（已是最新）'))
    if note:
        log('   ℹ️  %s' % note)
    if args.userinfo:
        good, res = enrich_userinfo(item)
        if good:
            log('   📇 remark 已补全: 手机掩码=%s 注册=%s 最近登录=%s(%s)'
                % (res.get('phoneMasked') or '-', res.get('registerTime') or '-',
                   res.get('lastLoginTime') or '-', res.get('lastLoginType') or '-'))
        else:
            log('   ⚠️  remark 补全失败: %s' % res)
    if args.refresh:
        log('⑦ 用本机设备私钥强制续期（ExchangeToken + DeviceProof）…')
        got, msg = force_refresh(item)
        if not got:
            log('   ❌ 续期失败: %s' % msg)
            raise RuntimeError(msg)
        log('   ✅ 续期成功 accessToken=%s exp=%s(%s)'
            % (fp(item['accessToken']), jwt_exp(item['accessToken']), fmt_ts(jwt_exp(item['accessToken']))))
    if not args.dry_run:
        save_items(args.config, items)
        log('⑧ 已写回 %s' % args.config)
    else:
        log('⑧ --dry-run：未写文件')
    if args.verify or args.refresh:
        c = credits_check(item.get('accessToken') or '', item.get('deviceId') or did)
        log('⑨ 积分接口验证: http=%s code=%s 已用=%s 剩余=%s'
            % (c.get('status'), c.get('code'), c.get('used'), c.get('remain')))
        if c.get('auth_fail') or c.get('status', 0) >= 400:
            raise RuntimeError('token 验证失败: %s' % c)
    return item


def main():
    global _LOG_PATH
    ap = argparse.ArgumentParser(description='通过 MQTT RPC 抓取远端 Trae 登录凭据并合并到 !trae.json')
    ap.add_argument('--config', default=CONFIG_FILE, help='配置文件（默认同目录 !trae.json）')
    ap.add_argument('--host', action='append', default=[],
                    help='只处理指定通道：mqtt:<topic> 或 local（可重复/逗号分隔；裸 topic 自动补 mqtt:）')
    ap.add_argument('--dry-run', action='store_true', help='只解析，不写回配置')
    ap.add_argument('--verify', action='store_true', help='写回后查一次积分接口验证 token')
    ap.add_argument('--refresh', action='store_true', help='抓完后用设备证明强制续期一次')
    ap.add_argument('--local', action='store_true', help='只读本机 storage.json（不联网、不走 MQTT）')
    ap.add_argument('--add', action='store_true', help='遇到 !trae.json 里没有的账号时允许新增（默认只更新已有账号）')
    ap.add_argument('--userinfo', action='store_true', help='调用 GetUserInfo 补全 remark（单独使用=只补全所有账号）')
    ap.add_argument('--storage-path', default='', help='指定 storage.json 路径（--local 时使用）')
    ap.add_argument('--list', action='store_true', help='列出配置里的主机与账号对应关系')
    ap.add_argument('--no-log', action='store_true', help='不写 .trae_remote_fetch.log')
    args = ap.parse_args()
    if not args.no_log:
        _LOG_PATH = LOG_FILE

    try:
        items = load_items(args.config)
    except Exception as e:
        print('❌ 读取配置失败: %s' % e)
        return 2
    hosts = mqtt_hosts(items)
    if args.list:
        print('配置文件: %s' % args.config)
        for a in items:
            cfg = a.get('mqtt') or {}
            rem = a.get('remark') if isinstance(a.get('remark'), dict) else {}
            print('  - uid=%s name=%s host=%s(%s) topic=%s key=%s did=%s fetched=%s exp=%s'
                  % (a.get('uid') or '-', acct_name(a), a.get('host') or '-',
                     rem.get('hostName') or '-',
                     cfg.get('requestTopic') or '-', mask_key(cfg.get('privateKey')),
                     a.get('deviceId') or '-', rem_time(a, 'fetchedAt'),
                     rem_time(a, 'tokenExpiresAt')))
        if not hosts:
            print('  (没有带 mqtt 配置的账号)')
        return 0
    want = []
    for h in args.host:
        want += [canon_host(x) for x in str(h).replace('，', ',').split(',') if x.strip()]
    if args.local or 'local' in want:
        log('══ Trae 本机凭据读取 ══')
        log('配置: %s（%d 个账号）' % (args.config, len(items)))
        try:
            run_local(items, args)
        except Exception as e:
            log('❌ 本机读取失败: %s' % e)
            return 1
        want = [x for x in want if x != 'local']
        if args.local or not want:
            log('完成: 成功 1，失败 0')
            return 0
    if args.userinfo and not args.host:
        return enrich_all(items, args)
    if not hosts:
        print('❌ !trae.json 里没有带 mqtt 配置的账号。')
        print('   请给远端账号加 mqtt.requestTopic/privateKey/minBrokerCount（密钥不要写进代码）。')
        return 2

    targets = [h for h in hosts if not want or h in want]
    if want and not targets:
        print('❌ 未匹配到通道: %s（可用: %s）' % (','.join(want), ','.join(hosts)))
        return 2

    log('══ Trae 远端凭据抓取 ══')
    log('配置: %s（%d 个账号，%d 个 MQTT 主机）' % (args.config, len(items), len(targets)))
    ok, fail = 0, 0
    for topic in targets:
        try:
            run_one(topic, hosts[topic], items, args)
            ok += 1
        except Exception as e:
            fail += 1
            log('❌ [%s] 抓取失败: %s' % (topic, e))
    log('完成: 成功 %d，失败 %d' % (ok, fail))
    if not args.no_log:
        log('日志: %s' % LOG_FILE, quiet=True)
    return 0 if fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
