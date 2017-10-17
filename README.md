
[さくらインターネット公式で自動更新サービスが提供](https://www.sakura.ne.jp/function/freessl.html)されたので，今後はそちらを使ってください．


# さくらのレンタルサーバへのSSL証明書の自動設定

[![Apache License](http://img.shields.io/badge/license-APACHE2-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![CircleCI](https://circleci.com/gh/shirayu/sakura_sslcert_set.svg?style=svg)](https://circleci.com/gh/shirayu/sakura_sslcert_set)


[acme.sh](https://acme.sh)等で生成したSSL証明書を，さくらのレンタルサーバーへ自動で設定します．
このスクリプトをcronに登録することで，手作業で証明書を更新する必要が無くなります．


## Quick Start

```sh
cp config.template.json config.json
chmod 600 config.json
vi config.json # IDとパスワードを記入

python3 ./setssl.py \
    -c ./config.json -t example.com \
    --secret ~/.acme.sh/www.example.com/www.example.com.key \
    --cacert1 ~/.acme.sh/www.example.com/www.example.com.cer \
    --cacert2 ~/.acme.sh/www.example.com/ca.cer \
    --history history.txt \
    --verbose
```


## 注意事項
- ``config.json``に生のパスワードを記入したファイルを作成するため，セキリティ上の配慮を十分行い，自己責任でご利用ください


## License
- [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)
