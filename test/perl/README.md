# Perl-тесты C-модуля nginx-s3-gateway

Набор тестов в стиле `Test::Nginx` для проверки поведения C-модуля `ngx_http_s3_gateway_c_module`.

## Структура

- `run.sh` — запуск всех тестов в каталоге `t/`.
- `t/*.t` — сценарные HTTP-тесты.

## Покрытие тестами

- `t/001_redirect_readonly.t`
  - read-only ограничения по методам
  - переходы в `@s3`, `@s3PreListing`, `@s3_sliced`, `@error405`

- `t/002_filters.t`
  - фильтрация `x-amz-*` заголовков
  - модификация пустого листинга (`junk`)

- `t/003_variables.t`
  - генерация `$s3uri`
  - формат `$s3auth` (SigV2)
  - формат `$httpDate`

- `t/004_sigv4_cache_format.t`
  - формат `$s3auth` (SigV4)
  - формат значения `$signing_key_hash`

- `t/005_credentials_keyval.t`
  - чтение credentials из переменной keyval-стиля
  - поведение при некорректном/пустом JSON

- `t/006_trailslash_control.t`
  - логика `trailslashControl`

- `t/007_filters_allowed_and_encoded_head_dir.t`
  - `HEADER_PREFIXES_ALLOWED`
  - HEAD по percent-encoded directory path

- `t/008_redirect_root_404.t`
  - ветка `@error404` для корневого `/` при выключенном листинге и index-page

- `t/009_s3uri_virtual_style.t`
  - `$s3uri` для `S3_STYLE=virtual`

- `t/010_sigv4_session_token_headers.t`
  - SigV4 c `AWS_SESSION_TOKEN`
  - `SignedHeaders` с `x-amz-security-token`

- `t/011_sigv2_for_index_page.t`
  - эквивалентность подписи SigV2 для directory + `forIndexPage=true` и явного `index.html`

- `t/012_header_prefixes_to_strip_custom.t`
  - удаление заголовков по кастомному `HEADER_PREFIXES_TO_STRIP`
  - сохранение нецелевых заголовков

- `t/013_trailslash_append_disabled.t`
  - поведение `trailslashControl` при `APPEND_SLASH_FOR_POSSIBLE_DIRECTORY=false`

- `t/014_sigv4_for_index_page.t`
  - эквивалентность подписи SigV4 для directory + `forIndexPage=true` и явного `index.html`

## Требования

- Perl
- `Test::Nginx` (из `nginx-tests`)
- Собранный модуль `.so`
  - по умолчанию: `nginx/objs/ngx_http_s3_gateway_c_module.so`

## Запуск

### Полный запуск

```bash
nginx-s3-gateway_с/test/perl/run.sh
```

### Ручной запуск через `prove`

```bash
PERL5LIB="$PWD/nginx-tests/lib" \
S3GW_MODULE_SO="$PWD/nginx/objs/ngx_http_s3_gateway_c_module.so" \
prove -r nginx-s3-gateway_с/test/perl/t
```

## Если `Test::Nginx` отсутствует

Тесты помечаются как `skipped`. Это штатное поведение раннера.

Для быстрой технической проверки файлов можно выполнить:

```bash
for f in nginx-s3-gateway_с/test/perl/t/*.t; do
  perl -c "$f"
done
```
