#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Set SSL cert to sakura internet
'''
# pylint: disable-msg=too-many-arguments

import argparse
import json
import sys
import re
import os.path
import hashlib
import requests

LOGIN_URL = 'https://secure.sakura.ad.jp/rscontrol/'
LOGIN_POST_URL = LOGIN_URL
SET_START_URL = 'https://secure.sakura.ad.jp/rscontrol/rs/ssl?SNIDomain='
SET_URL = 'https://secure.sakura.ad.jp/rscontrol/rs/ssl?Install=1&SNIDomain='
SET_CACERT2_URL = 'https://secure.sakura.ad.jp/rscontrol/rs/ssl?CACert=1&SNIDomain='
RE_TOKEN = re.compile(r'name="Token" value="([^"]*)"')
TIMEOUT = 180


def login(session, domain, password):
    '''
    login
    '''
    res = session.get(LOGIN_URL, timeout=TIMEOUT)
    body = res.text
    token = RE_TOKEN.search(body).group(1)

    data = {
        'domain': domain,
        'password': password,
        'Token': token,
        'Submit': 'index',
    }
    res = session.post(LOGIN_POST_URL, data, timeout=TIMEOUT)
    body = res.text
    if "ドメイン名もしくはパスワードが間違っています" in body:
        return False
    return True


def select_create_new_setting(session, url, token, verbose=False):
    '''
    「秘密鍵を含む新しい設定の作成」を選択
    '''
    if verbose:
        sys.stdout.write("- 「秘密鍵を含む新しい設定の作成」を選択\n")
    res = session.post(url, {'Target': 'new',
                             'Token': token,
                             'Submit_newdir': '秘密鍵を含む新しい設定の作成',
                            }, timeout=TIMEOUT)
    body = res.text
    if '新しい設定を作成中です' not in body:
        if verbose:
            print(' 遷移エラー')
        sys.exit(1)
    return body


def send_secret_key(session, url, secret, token, verbose=False):
    '''
    秘密鍵を送る
    '''
    if verbose:
        sys.stdout.write("- 秘密鍵送信\n")

    session.headers.update({'referer': url})
    res = session.post(url,
                       files={
                           'file': ('secret.key', open(secret, 'rb'))
                       },
                       data={
                           'Token': token,
                           'Password': '',
                           'Submit_upload': '秘密鍵をアップロードする',
                       },
                       timeout=TIMEOUT)
    body = res.text
    if '秘密鍵を既にお持ちの場合には' in body:
        print(" 秘密鍵の送信に失敗")
        sys.exit(1)
    elif 'error-message' in body:
        if 'SSLが見つかりません' in body:
            print(' エラー: SSLが見つかりません')
        else:
            print(" エラー")
        sys.exit(1)
    return body


def install_cacert1(session, token, url, cacert, verbose=False):
    '''
    証明書認証局から送られた証明書の送信
    '''
    if verbose:
        sys.stdout.write("- 証明書認証局から送られた証明書の送信\n")

    with open(cacert, 'r') as textf:
        res = session.post(url, {
            'Token': token,
            'Cert': textf.read(),
            'Submit_install.x': '40',
            'Submit_install.y': '7',
        }, timeout=TIMEOUT)
        return res.text


def enable_new_setting(session, token, url, verbose=False):
    '''
    新しい設定の有効化
    '''
    if verbose:
        sys.stdout.write("- 設定の有効化\n")

    res = session.post(url, {
        'Submit': 'applynew',
        'Token': token,
    }, timeout=TIMEOUT)
    return res.text


def install_cacert2(session, url, cacert2, verbose=False):
    '''
    中間証明書の送信
    '''
    if verbose:
        sys.stdout.write("- 中間証明書の送信\n")

    res = session.get(url, timeout=TIMEOUT)
    body = res.text
    token = RE_TOKEN.search(body).group(1)

    with open(cacert2, 'r') as textf:
        res = session.post(url, {
            'Token': token,
            'Cert': textf.read(),
            'Submit_cacert.x': '40',
            'Submit_cacert.y': '7',
        }, timeout=TIMEOUT)
        return res.text


def operation(session, target_domain, secret, cacert1, cacert2, verbose=False):
    '''
    設定を行う
    '''
    my_set_url = SET_START_URL + target_domain
    my_install_url = SET_URL + target_domain
    my_set_cacert2_url = SET_CACERT2_URL + target_domain

    res = session.get(my_set_url, timeout=TIMEOUT)
    body = res.text
    token = RE_TOKEN.search(body).group(1)

    if '秘密鍵を含む新しい設定の作成' in body:
        body = select_create_new_setting(session, my_set_url, token, verbose)
        token = RE_TOKEN.search(body).group(1)

    if '秘密鍵を既にお持ちの場合には' not in body:
        sys.stdout.write("  Unexpected page\n")
        sys.exit(1)

    body = send_secret_key(session, my_set_url, secret, token, verbose)
    token = RE_TOKEN.search(body).group(1)

    if '証明書認証局から送られた証明書を以下に貼り付け' not in body:
        if verbose:
            print('遷移エラー')
        sys.exit(1)

    body = install_cacert1(session, token, my_install_url, cacert1, verbose)
    token = RE_TOKEN.search(body).group(1)

    if '新しい設定はまだ完了していません' in body:
        body = enable_new_setting(session, token, my_set_url, verbose)

    if '新しい設定を作成中です' in body:
        print(" 設定に失敗しました")
        sys.exit(1)

    if '証明書ではありませんでした' in install_cacert2(session, my_set_cacert2_url, cacert2, verbose):
        print(" 設定に失敗しました")
        sys.exit(1)

    if verbose:
        print("設定が完了しました．")
        print("「SNI SSLを利用する」にチェックを入れていない場合は，入れてください")


def is_in_history(fname, target, md5):
    '''
    Check whether the secret key is used
    '''
    if not os.path.exists(fname):
        return False

    with open(fname) as historyf:
        for line in historyf:
            items = line[:-1].split()
            if len(items) != 2:
                continue
            if target == items[0] and md5 == items[1]:
                return True
    return False


def main():
    '''
    Parse arguments
    '''
    oparser = argparse.ArgumentParser()
    oparser.add_argument("-c", "--config", dest="config", required=True)
    oparser.add_argument("-t", "--target", dest="target", required=True)
    oparser.add_argument("--secret", dest="secret", required=True)
    oparser.add_argument("--cacert1", dest="cacert1", required=True)
    oparser.add_argument("--cacert2", dest="cacert2", required=True)
    oparser.add_argument("--verbose", dest="verbose", action="store_true", default=False)
    oparser.add_argument("--history", dest="history")
    opts = oparser.parse_args()

    if not os.path.exists(opts.secret):
        raise IOError
    if not os.path.exists(opts.cacert1):
        raise IOError
    if not os.path.exists(opts.cacert2):
        raise IOError

    md5 = None
    with open(opts.secret, 'rb') as secretf:
        md5 = hashlib.md5(secretf.read()).hexdigest()
    if opts.history and is_in_history(opts.history, opts.target, md5):
        if opts.verbose:
            print("使用済みのキーです")
        sys.exit(0)

    cfg = None
    with open(opts.config) as fhdl:
        cfg = json.loads(fhdl.read())

    session = requests.session()

    if opts.verbose:
        sys.stdout.write("- ログイン\n")
    if not login(session, cfg["domain"], cfg["password"]):
        sys.stdout.write("   エラー\n")
        sys.exit(1)

    operation(session, opts.target, opts.secret, opts.cacert1, opts.cacert2, opts.verbose)
    if opts.history:
        with open(opts.history, 'a') as historyf:
            historyf.write("%s\t%s\n" % (opts.target, md5))


if __name__ == '__main__':
    main()
