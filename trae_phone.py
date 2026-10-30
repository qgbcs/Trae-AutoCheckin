#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trae 账号手机号 · trae_phone.py
────────────────────────────────────────────────────────────
背景（实测结论）：
  Trae 服务端只返回打码手机号。逐个验证过：
    POST /cloudide/api/v3/trae/GetUserInfo  → NonPlainTextMobile（如 175******96）
    POST /cloudide/api/v3/trae/CheckLogin   → 只有 UserID/Region/绑定设备等，无手机号
    POST https://api.trae.com.cn/icube/api/v1/user → 只有 {"loginAllowed":true}
  客户端本地也不存全号：
    storage.json 解密的 account 里只有 nonPlainTextMobile
    Trae 日志（main.log 的 updateLocalCredential.userInfo）里也只有 NonPlainTextMobile
    state.vscdb / Local Storage 里没有手机号
  因此“用 token 拉完整手机号”这条路不存在；本脚本做三件事：
    1) 列出每个账号服务端可见的掩码，并说明全号是否可得；
    2) 在本机/远端日志、state.vscdb 里按掩码找候选全号（命中才输出）；
    3) 把已知全号写进 remark.phone，并用掩码做一致性校验，防止记错。

用法：
  python trae_phone.py                       # 列出账号：name / uid / 掩码 / remark.phone / 一致性
  python trae_phone.py --probe               # 逐项打印每个来源的原始结果（证据）
  python trae_phone.py --scan-local          # 扫本机 Trae 日志与 state.vscdb，找匹配掩码的号码
  python trae_phone.py --scan-remote mqtt:lenovo   # 走 MQTT 扫远端机器日志（复用 mqtt 配置）
  python trae_phone.py --set <uid> 13800138000     # 记录全号；与掩码不一致会拒绝（--force 可强制）
  python trae_phone.py --verify              # 重新查一次掩码，校验 remark.phone
  python trae_phone.py --no-net              # 完全离线，只用 remark 里已有的掩码

数据约定：
  - 全号只写在 remark.phone（注释区，不影响任何脚本运行），同时写 remark.phoneSetAt 与
    remark.phoneSource（manual / scan-local / scan-remote）。
  - 掩码字段仍是 remark.phoneMasked，来自 GetUserInfo。
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import trae_remote_creds as trc  # noqa: E402

CONFIG_FILE = os.path.join(HERE, '!trae.json')
EP_CHECKLOGIN = trc.UG_HOST + '/cloudide/api/v3/trae/CheckLogin'
ICUBE_BASE = 'https://api.trae.com.cn'
EP_ICUBE_USER = ICUBE_BASE + '/icube/api/v1/user'

PHONE_RE = re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)')
MASK_RE = re.compile(r'^1[3-9]\d{0,2}\*+[0-9]{0,4}$')


# ══════════════════ 基础工具 ══════════════════
def mask_parts(mask):
    """175******96 → ('175', '96')；不是掩码则返回 None。"""
    s = str(mask or '').strip()
    if '*' not in s or not MASK_RE.match(s):
        return None
    return s[:3], s[-2:]


def phone_ok(phone, mask):
    """校验全号格式，并和掩码的前 3 位/后 2 位比对。mask 为空则只校验格式。"""
    p = str(phone or '').strip()
    if not PHONE_RE.fullmatch(p):
        return False, '不是合法的 11 位手机号'
    parts = mask_parts(mask)
    if not parts:
        return True, '掩码不可用，仅格式校验'
    if p[:3] != parts[0] or p[-2:] != parts[1]:
        return False, '与掩码 %s 不一致（应为 %s******%s）' % (mask, parts[0], parts[1])
    return True, '与掩码一致'


def post_json(url, body, headers, timeout=25):
    req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), method='POST',
                                 headers={'Content-Type': 'application/json', **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode('utf-8', 'replace')
    except Exception as e:
        return -1, str(e)


def fetch_mask(token):
    """GetUserInfo 的 NonPlainTextMobile（服务端唯一给手机号的地方，且是掩码）。"""
    info = trc.fetch_userinfo(str(token or '').strip())
    return str((info or {}).get('NonPlainTextMobile') or '').strip()


def fetch_checklogin(token):
    st, txt = post_json(EP_CHECKLOGIN, {'ReqSource': 'IDE', 'IDEVersion': '3.4.9'},
                        {'x-cloudide-token': str(token or '').strip()})
    try:
        return st, json.loads(txt).get('Result') or {}
    except Exception:
        return st, {'raw': txt[:200]}


def fetch_icube(token, uid, device_id=''):
    body = {'packageType': 'stable_cn', 'productCode': 'TRAE', 'platform': 'Win',
            'appVersion': '3.4.9', 'arch': 'x64', 'uid': uid, 'userRegion': 'CN',
            'organization': '', 'scope': '', 'did': device_id}
    st, txt = post_json(EP_ICUBE_USER, body, {'x-icube-token': str(token or '').strip()})
    try:
        return st, json.loads(txt)
    except Exception:
        return st, {'raw': txt[:200]}


def local_mask():
    """本机 storage.json 解密后的 nonPlainTextMobile（同样只有掩码）。"""
    try:
        blob = trc.local_blob('')
        acc_text, _t = trc.dec_storage(blob['cloudide'])
        acc = json.loads(acc_text)
        return str((acc.get('account') or {}).get('nonPlainTextMobile') or '').strip()
    except Exception as e:
        return '(%s)' % e


# ══════════════════ 本机扫描 ══════════════════
def log_roots():
    home = os.path.expanduser('~')
    ad = os.environ.get('APPDATA') or os.path.join(home, 'AppData', 'Roaming')
    roots = []
    for n in ('Trae CN', 'TRAE SOLO CN', 'TRAE SOLO', 'Trae', '.trae-cn'):
        roots += [os.path.join(ad, n, 'logs'),
                  os.path.join(home, '.config', n, 'logs'),
                  os.path.join(home, 'Library', 'Application Support', n, 'logs')]
    return [p for p in roots if os.path.isdir(p)]


def scan_text_roots(roots, masks, max_size=20 * 1024 * 1024, max_hits=50):
    """在文本文件里找 11 位号码，只保留能对上掩码前缀/后缀的。"""
    hits = []
    for root in roots:
        for dirpath, _, names in os.walk(root):
            for n in names:
                p = os.path.join(dirpath, n)
                try:
                    if os.path.getsize(p) > max_size:
                        continue
                    text = open(p, 'rb').read().decode('utf-8', 'ignore')
                except Exception:
                    continue
                for num in set(PHONE_RE.findall(text)):
                    for mask in masks:
                        parts = mask_parts(mask)
                        if parts and num[:3] == parts[0] and num[-2:] == parts[1]:
                            hits.append({'file': p, 'phone': num, 'mask': mask})
                if len(hits) >= max_hits:
                    return hits
    return hits


def scan_state_vscdb(masks, max_hits=50):
    """state.vscdb 里是否存在匹配掩码的号码。"""
    import sqlite3
    db = os.path.join(os.environ.get('APPDATA') or '', 'Trae CN', 'User', 'globalStorage', 'state.vscdb')
    if not os.path.isfile(db):
        return []
    hits = []
    try:
        con = sqlite3.connect('file:%s?mode=ro' % db, uri=True)
        rows = con.execute('select key, value from ItemTable').fetchall()
        con.close()
    except Exception:
        return []
    for k, v in rows:
        text = str(v)
        if 'phone' not in text.lower() and 'mobile' not in text.lower():
            continue
        for num in set(PHONE_RE.findall(text)):
            for mask in masks:
                parts = mask_parts(mask)
                if parts and num[:3] == parts[0] and num[-2:] == parts[1]:
                    hits.append({'file': 'state.vscdb:%s' % k, 'phone': num, 'mask': mask})
        if len(hits) >= max_hits:
            break
    return hits


# ══════════════════ 远端扫描（MQTT RPC） ══════════════════
def remote_scan_code(masks):
    return r'''
import json, os, platform, re
MASKS = %s
PAT = re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)')


def roots():
    home = os.path.expanduser("~")
    ad = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    out = []
    for n in ("Trae CN", "TRAE SOLO CN", "TRAE SOLO", "Trae", ".trae-cn"):
        out += [os.path.join(ad, n, "logs"), os.path.join(home, ".config", n, "logs"),
                os.path.join(home, "Library", "Application Support", n, "logs")]
    return [p for p in out if os.path.isdir(p)]


hits = []
for root in roots():
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(dp, f)
            try:
                if os.path.getsize(p) > 20 * 1024 * 1024:
                    continue
                s = open(p, "rb").read().decode("utf-8", "ignore")
            except Exception:
                continue
            for num in set(PAT.findall(s)):
                for m in MASKS:
                    if num[:3] == m[:3] and num[-2:] == m[-2:]:
                        hits.append({"file": p, "phone": num, "mask": m})
            if len(hits) >= 50:
                break
print(json.dumps({"ok": True, "host": platform.node(), "roots": roots(),
                  "hits": hits[:50]}, ensure_ascii=False))
''' % json.dumps([m for m in masks if m], ensure_ascii=False)


def rpc_run(host_cfg, code, timeout=None):
    repo = (host_cfg.get('repoPath') or os.environ.get('TRAE_MQTT_REPO') or '').strip()
    if repo and os.path.isdir(repo) and repo not in sys.path:
        sys.path.insert(0, repo)
    from client import client_mqtt
    topic = str(host_cfg.get('requestTopic') or '').strip()
    key = host_cfg.get('privateKey')
    if not topic or not key:
        raise RuntimeError('mqtt.requestTopic / mqtt.privateKey 未配置')
    kw = {}
    reply = str(host_cfg.get('replyTopic') or '').strip()
    if reply:
        kw['reply_topic'] = reply
    res = client_mqtt.rpc(code, request_topic=topic, timeout=float(timeout or host_cfg.get('timeout') or 20),
                          k=key, mb=int(host_cfg.get('minBrokerCount') or 6), **kw)
    if not res.get('ok'):
        raise RuntimeError('RPC 失败: %s' % (res.get('stdout') or res)[:300])
    lines = [x for x in (res.get('stdout') or '').splitlines() if x.strip()]
    if not lines:
        raise RuntimeError('远端没有输出')
    data = json.loads(lines[-1])
    if not data.get('ok'):
        raise RuntimeError('远端扫描失败: %s' % data.get('error'))
    return data


# ══════════════════ 展示 ══════════════════
def show(accounts, online=True):
    print('%-18s %-14s %-16s %-16s %-8s' % ('账号', 'uid', '掩码', 'remark.phone', '一致性'))
    for a in accounts:
        rem = trc.rem_of(a)
        mask = str(rem.get('phoneMasked') or '').strip()
        if online and not mask and a.get('accessToken'):
            mask = fetch_mask(a.get('accessToken'))
            if mask:
                rem['phoneMasked'] = mask
        phone = str(rem.get('phone') or '').strip()
        if phone:
            ok, why = phone_ok(phone, mask)
            verdict = '✅' if ok else '❌ %s' % why
        else:
            verdict = '-'
        print('%-18s %-14s %-16s %-16s %-8s'
              % (trc.acct_name(a), str(a.get('uid') or '-'), mask or '-', phone or '未记录', verdict))
    print('\n说明：服务端 GetUserInfo/CheckLogin/icube user 都只给掩码；全号可用 --set 记录。')


def probe(accounts, online=True):
    print('══ 逐项取证：完整手机号是否可得 ══')
    lm = local_mask() if online else '-'
    print('① 本机 storage.json account.nonPlainTextMobile = %s' % lm)
    for a in accounts:
        tok = str(a.get('accessToken') or '').strip()
        rem = trc.rem_of(a)
        print('\n【%s】uid=%s host=%s' % (trc.acct_name(a), a.get('uid') or '-', a.get('host') or '-'))
        if not online or not tok:
            print('   (离线/无 token，跳过接口)')
            continue
        mask = fetch_mask(tok)
        print('   ② GetUserInfo      → NonPlainTextMobile=%s（只有掩码）' % (mask or '(空)'))
        if mask:
            rem['phoneMasked'] = mask
        st, res = fetch_checklogin(tok)
        keys = ', '.join(sorted(res.keys())) if isinstance(res, dict) else '-'
        print('   ③ CheckLogin       → http=%s 字段=%s（无手机号）' % (st, keys))
        st, res = fetch_icube(tok, a.get('uid') or '', a.get('deviceId') or '')
        print('   ④ icube/api/v1/user → http=%s %s'
              % (st, json.dumps(res.get('data') if isinstance(res, dict) else res, ensure_ascii=False)[:120]))
    print('\n结论：接口侧拿不到全号；本地凭据与日志也只存掩码。')


# ══════════════════ 入口 ══════════════════
def main():
    ap = argparse.ArgumentParser(description='Trae 账号手机号：查掩码、扫描候选、记录/校验全号')
    ap.add_argument('--config', default=CONFIG_FILE, help='配置文件（默认同目录 !trae.json）')
    ap.add_argument('--probe', action='store_true', help='逐项打印每个来源的原始结果（证据）')
    ap.add_argument('--scan-local', action='store_true', help='扫本机 Trae 日志与 state.vscdb')
    ap.add_argument('--scan-remote', default='', metavar='mqtt:<topic>', help='走 MQTT 扫远端日志')
    ap.add_argument('--set', nargs=2, metavar=('UID', 'PHONE'), help='记录完整手机号到 remark.phone')
    ap.add_argument('--verify', action='store_true', help='重新查掩码并校验 remark.phone')
    ap.add_argument('--force', action='store_true', help='--set 时跳过掩码一致性检查')
    ap.add_argument('--no-net', action='store_true', help='完全离线（不调用任何接口）')
    ap.add_argument('--dry-run', action='store_true', help='只打印，不写回配置')
    args = ap.parse_args()

    try:
        accounts = trc.load_items(args.config)
    except Exception as e:
        print('❌ 读取配置失败: %s' % e)
        return 2
    online = not args.no_net
    changed = False

    if args.set:
        uid, phone = args.set[0].strip(), args.set[1].strip()
        target = None
        for a in accounts:
            if str(a.get('uid') or '').strip() == uid:
                target = a
                break
        if target is None:
            print('❌ 找不到 uid=%s' % uid)
            return 2
        rem = trc.rem_of(target)
        mask = str(rem.get('phoneMasked') or '').strip()
        if online and not mask and target.get('accessToken'):
            mask = fetch_mask(target.get('accessToken'))
        ok, why = phone_ok(phone, mask)
        if not ok and not args.force:
            print('❌ %s：%s（确认无误可加 --force）' % (phone, why))
            return 1
        rem['phone'] = phone
        rem['phoneMasked'] = mask or rem.get('phoneMasked') or ''
        rem['phoneSetAt'] = trc.fmt_ts(int(time.time()))
        rem['phoneSource'] = 'manual'
        changed = True
        print('✅ %s uid=%s 记录全号 %s（%s）' % (trc.acct_name(target), uid, phone, why))
        if not args.dry_run:
            trc.save_items(args.config, accounts)
            print('💾 已写回 %s' % args.config)
        else:
            print('--dry-run：未写文件')
        return 0

    if args.probe:
        probe(accounts, online)
        if not args.dry_run and online:
            trc.save_items(args.config, accounts)
        return 0

    if args.verify:
        print('══ 校验 remark.phone ══')
        bad = 0
        for a in accounts:
            rem = trc.rem_of(a)
            phone = str(rem.get('phone') or '').strip()
            if not phone:
                continue
            mask = str(rem.get('phoneMasked') or '').strip()
            if online and a.get('accessToken'):
                fresh = fetch_mask(a.get('accessToken'))
                if fresh:
                    mask = fresh
                if mask:
                    rem['phoneMasked'] = mask
            ok, why = phone_ok(phone, mask)
            bad += 0 if ok else 1
            print('  %s uid=%s phone=%s mask=%s → %s'
                  % (trc.acct_name(a), a.get('uid') or '-', phone, mask or '-',
                     '✅ ' + why if ok else '❌ ' + why))
        if changed or online:
            if not args.dry_run:
                trc.save_items(args.config, accounts)
        print('完成：%s' % ('全部一致' if bad == 0 else '%d 个不一致' % bad))
        return 0 if bad == 0 else 1

    if args.scan_local:
        masks = []
        for a in accounts:
            rem = trc.rem_of(a)
            m = str(rem.get('phoneMasked') or '').strip()
            if online and not m and a.get('accessToken'):
                m = fetch_mask(a.get('accessToken'))
                if m:
                    rem['phoneMasked'] = m
            if m:
                masks.append(m)
        print('══ 本机扫描：按掩码找 11 位号码 ══')
        print('掩码: %s' % ', '.join(masks) if masks else '掩码: (无)')
        hits = scan_text_roots(log_roots(), masks) + scan_state_vscdb(masks)
        for h in hits:
            print('  ✅ %s ← %s（掩码 %s）' % (h['phone'], h['file'], h['mask']))
        if not hits:
            print('  (未找到) Trae 日志/state.vscdb 里只有掩码，没有匹配的全号')
        if online and not args.dry_run:
            trc.save_items(args.config, accounts)
        return 0

    if args.scan_remote:
        topic = trc.canon_host(args.scan_remote)
        targets = [a for a in accounts if trc.canon_host(a.get('host')) == topic]
        if not targets:
            print('❌ 没有 host=%s 的账号（可用: %s）'
                  % (topic, ', '.join(sorted({trc.canon_host(a.get('host')) for a in accounts if a.get('host')}))))
            return 2
        masks = []
        for a in targets:
            rem = trc.rem_of(a)
            m = str(rem.get('phoneMasked') or '').strip()
            if online and not m and a.get('accessToken'):
                m = fetch_mask(a.get('accessToken'))
                if m:
                    rem['phoneMasked'] = m
            if m:
                masks.append(m)
        cfg = next((a.get('mqtt') for a in targets if a.get('mqtt')), {}) or {}
        print('══ 远端扫描 %s（%d 个掩码）══' % (topic, len(masks)))
        data = rpc_run(cfg, remote_scan_code(masks))
        print('  远端机器: %s' % data.get('host'))
        print('  扫描目录: %s' % ', '.join(data.get('roots') or []))
        hits = data.get('hits') or []
        for h in hits:
            print('  ✅ %s ← %s（掩码 %s）' % (h.get('phone'), h.get('file'), h.get('mask')))
        if not hits:
            print('  (未找到) 远端日志里也只有掩码，没有匹配的全号')
        if online and not args.dry_run:
            trc.save_items(args.config, accounts)
        return 0

    show(accounts, online)
    if online and not args.dry_run:
        trc.save_items(args.config, accounts)
    return 0


if __name__ == '__main__':
    sys.exit(main())
