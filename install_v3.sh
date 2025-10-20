#!/usr/bin/env bash
# Caddy + File Browser автодеплой статического сайта (index.html + data.json)
# Версия: 3.0 (идемпотентная, с режимами Cloudflare и авто-подхватом локальных файлов)
# Поддержка: Ubuntu 22.04/24.04, Debian 12

set -Eeuo pipefail

### ───────── helpers ─────────
info(){ echo -e "\033[1;32m[INFO]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
err(){  echo -e "\033[1;31m[ERR ]\033[0m $*"; }
trap 'err "Скрипт завершился с ошибкой на строке $LINENO"' ERR
timestamp(){ date +"%Y%m%d-%H%M%S"; }

require_root(){
  if [[ $EUID -ne 0 ]]; then err "Запустите скрипт от root (sudo ./install_v3.sh)"; exit 1; fi
}

check_os(){
  . /etc/os-release || { err "Не удалось определить ОС"; exit 1; }
  case "${ID}-${VERSION_ID}" in
    ubuntu-22.04|ubuntu-24.04|debian-12) info "ОС: ${PRETTY_NAME}";;
    *) warn "ОС ${PRETTY_NAME} не тестировалась. Продолжить? [y/N]"; read -r a; [[ ${a:-n} =~ ^[Yy]$ ]] || exit 1;;
  esac
}

have_pkg(){ dpkg -s "$1" >/dev/null 2>&1; }
ensure_pkgs(){
  local need=()
  for p in "$@"; do have_pkg "$p" || need+=("$p"); done
  if ((${#need[@]})); then
    info "Устанавливаю пакеты: ${need[*]}"
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${need[@]}"
  else
    info "Базовые пакеты уже установлены."
  fi
}
ensure_service_enabled_started(){
  local svc="$1"
  systemctl enable "$svc" >/dev/null 2>&1 || true
  systemctl is-active --quiet "$svc" || systemctl start "$svc"
}

port_in_use_by_non_caddy(){
  local port="$1"
  local out; out="$(ss -ltnp 2>/dev/null | awk -v p=":${port}" '$4 ~ p {print $0}')"
  [[ -z "$out" ]] && return 1
  if grep -q 'users:.*"caddy"' <<<"$out"; then return 1; else return 0; fi
}
ensure_ports_free(){
  local bad=0
  port_in_use_by_non_caddy 80 && { warn "Порт 80 занят чужим процессом"; bad=1; }
  port_in_use_by_non_caddy 443 && { warn "Порт 443 занят чужим процессом"; bad=1; }
  ((bad)) && { ss -ltnp | grep -E ':(80|443)\s' || true; err "Освободите порты 80/443 и повторите."; }
}

### ───────── ввод параметров ─────────
prompt_inputs(){
  echo "=== Ввод параметров ==="
  read -rp "Домен сайта (например: example.com): " DOMAIN; [[ -n "${DOMAIN}" ]] || { err "Домен обязателен"; exit 1; }

  read -rp "Создавать www-редирект (www.${DOMAIN} → ${DOMAIN})? [Y/n]: " WWW_REDIRECT; WWW_REDIRECT="${WWW_REDIRECT:-Y}"
  local default_edit="edit.${DOMAIN}"
  read -rp "Сабдомен для редактора файлов [${default_edit}]: " EDIT_SUB; EDIT_SUB="${EDIT_SUB:-$default_edit}"
  read -rp "Email для ACME/Let's Encrypt (необязательно): " ACME_EMAIL || true

  echo
  echo "Cloudflare режим:"
  echo "  0) Не используем Cloudflare"
  echo "  1) Cloudflare DNS, БЕЗ прокси (серый облачок) — HTTP-01"
  echo "  2) Cloudflare с прокси (оранжевый облачок) — DNS-01 через API-токен"
  read -rp "Выберите 0/1/2 [0]: " CF_MODE; CF_MODE="${CF_MODE:-0}"
  case "$CF_MODE" in
    0|1) : ;;
    2) read -rsp "Cloudflare API Token (Zone:Read + DNS:Edit): " CF_API_TOKEN; echo; [[ -n "${CF_API_TOKEN}" ]] || { err "API Token обязателен"; exit 1; } ;;
    *) err "Неверный выбор Cloudflare режима"; exit 1;;
  esac

  read -rp "Включить SPA fallback (все пути → /index.html)? [y/N]: " SPA_MODE; SPA_MODE="${SPA_MODE:-N}"

  echo
  echo "Источник файлов сайта:"
  echo "  0) Взять локальные ./index.html и ./data.json из текущей папки (рекомендуется для вашего формата)"
  echo "  1) Пустой шаблон (index.html + data.json)"
  echo "  2) Локальная папка на сервере"
  echo "  3) Git-репозиторий (public)"
  echo "  4) Архив по URL (zip/tar/tar.gz)"
  read -rp "Выберите 0/1/2/3/4 [0]: " SRC_MODE; SRC_MODE="${SRC_MODE:-0}"

  case "${SRC_MODE}" in
    0)
      [[ -f "./index.html" ]] || warn "ВНИМАНИЕ: ./index.html не найден — будет создан шаблон."
      [[ -f "./data.json"  ]] || warn "ВНИМАНИЕ: ./data.json не найден — будет создан скелет."
      ;;
    2)
      read -rp "Путь к локальной папке (например /root/site): " LOCAL_PATH
      [[ -d "${LOCAL_PATH}" ]] || { err "Папка не найдена: ${LOCAL_PATH}"; exit 1; }
      ;;
    3)
      read -rp "Git URL (например https://github.com/user/repo.git): " GIT_URL; [[ -n "${GIT_URL}" ]] || { err "Git URL обязателен"; exit 1; }
      read -rp "Ветка (по умолчанию — дефолтная): " GIT_BRANCH || true
      ;;
    4)
      read -rp "URL архива (zip/tar/tar.gz): " ARCH_URL; [[ -n "${ARCH_URL}" ]] || { err "URL обязателен"; exit 1; }
      ;;
    1) : ;;
    *) err "Неверный выбор источника"; exit 1;;
  esac

  echo
  read -rp "Логин администратора File Browser [admin]: " FB_ADMIN_USER; FB_ADMIN_USER="${FB_ADMIN_USER:-admin}"
  read -rsp "Пароль администратора File Browser: " FB_ADMIN_PASS; echo
  read -rsp "Повторите пароль администратора: " FB_ADMIN_PASS2; echo
  [[ "${FB_ADMIN_PASS}" == "${FB_ADMIN_PASS2}" ]] || { err "Пароли не совпадают"; exit 1; }

  read -rp "Включить дополнительную BasicAuth для ${EDIT_SUB}? [Y/n]: " BA_ENABLE; BA_ENABLE="${BA_ENABLE:-Y}"
  if [[ "${BA_ENABLE}" =~ ^[Yy]$ ]]; then
    read -rp "BasicAuth логин [editor]: " BA_USER; BA_USER="${BA_USER:-editor}"
    read -rsp "BasicAuth пароль: " BA_PASS; echo
    read -rsp "Повторите BasicAuth пароль: " BA_PASS2; echo
    [[ "${BA_PASS}" == "${BA_PASS2}" ]] || { err "Пароли BasicAuth не совпадают"; exit 1; }
  fi

  WEBROOT="/var/www/${DOMAIN}"
  if [[ -d "${WEBROOT}" ]] && [[ -n "$(ls -A "${WEBROOT}" 2>/dev/null || true)" ]]; then
    read -rp "Папка ${WEBROOT} уже не пуста. Синхронизировать выбранный источник в неё? [y/N]: " SYNC_EXISTING; SYNC_EXISTING="${SYNC_EXISTING:-N}"
  else
    SYNC_EXISTING="Y"
  fi

  echo
  echo "=== Резюме ==="
  echo "Домен:              ${DOMAIN}"
  echo "Редактор:           https://${EDIT_SUB}"
  echo "Cloudflare режим:   ${CF_MODE} (0=нет,1=DNS-only,2=DNS-01)"
  echo "SPA fallback:       $([[ "${SPA_MODE}" =~ ^[Yy]$ ]] && echo 'вкл' || echo 'выкл')"
  echo "Источник:           ${SRC_MODE}"
  echo "File Browser admin: ${FB_ADMIN_USER}"
  echo "BasicAuth:          $([[ "${BA_ENABLE}" =~ ^[Yy]$ ]] && echo "${BA_USER}" || echo 'выкл')"
  echo "WEBROOT:            ${WEBROOT} (sync: $([[ "${SYNC_EXISTING}" =~ ^[Yy]$ ]] && echo 'да' || echo 'нет'))"
  read -rp "Продолжаем установку? [Y/n]: " CONT; CONT="${CONT:-Y}"; [[ "${CONT}" =~ ^[Yy]$ ]] || exit 1
}

### ───────── пакеты/фаервол/DNS ─────────
apt_setup(){
  info "Проверка обновлений и установка базовых пакетов…"
  ensure_pkgs ufw curl unzip tar git dnsutils rsync caddy python3
  ensure_service_enabled_started caddy
}
firewall_setup(){
  info "Настройка UFW…"
  have_pkg ufw || apt-get install -y ufw
  ufw allow 22/tcp || true
  ufw allow 80,443/tcp || true
  ufw --force enable || true
}
dns_hint(){
  info "Проверка DNS A/AAAA…"
  command -v dig >/dev/null 2>&1 || { warn "dig не найден, пропускаю."; return 0; }
  local a1 a2; a1="$(dig +short A "${DOMAIN}" | tr '\n' ' ' || true)"; a2="$(dig +short A "${EDIT_SUB}" | tr '\n' ' ' || true)"
  echo "A ${DOMAIN}  → ${a1:-<нет>}"
  echo "A ${EDIT_SUB} → ${a2:-<нет>}"
  if [[ -z "${a1}" || -z "${a2}" ]]; then
    warn "DNS пока не указывает на сервер. HTTP-01 сработает после обновления записей; DNS-01 (CF режим 2) не зависит от A-записей."
  fi
}

### ───────── работа с сайт-файлами ─────────
validate_or_create_json(){
  local f="$1"
  if [[ -f "$f" ]]; then
    if ! python3 - <<PY >/dev/null 2>&1
import json,sys; json.load(open("$f","rb"))
PY
    then
      err "Файл $f содержит невалидный JSON. Исправьте и повторите."
    fi
  else
    info "Создаю скелет $f"
    cat > "$f" <<'JSON'
{
  "cases": []
}
JSON
  fi

  # лёгкая проверка структуры
  if ! python3 - <<'PY' "$f" >/dev/null 2>&1
import json,sys
j=json.load(open(sys.argv[1],"rb"))
assert isinstance(j,dict) and "cases" in j and isinstance(j["cases"],list)
for it in j["cases"]:
    assert isinstance(it,dict) and "case_code" in it and "data" in it and isinstance(it["data"],dict)
PY
  then
    warn "Структура data.json отличается от ожидаемой {cases:[{case_code, data{...}}]} — сайт может работать некорректно."
  fi
}

lint_index_html(){
  local f="$1"
  [[ -f "$f" ]] || return 0
  if grep -q '../www\.fsb\.ru/styles/' "$f"; then
    warn "В index.html найдены относительные пути вида ../www.fsb.ru/styles/... Проверьте стили — возможно, нужно заменить на локальные или CDN."
  fi
  if grep -q "jQuery(" "$f" && ! grep -qi "<script[^>]*jquery" "$f"; then
    warn "В index.html встречается вызов jQuery, но библиотека не подключена. Если этот обработчик нужен, добавьте jQuery или перепишите на чистом JS."
  fi
}

prepare_webroot(){
  info "Подготовка WEBROOT: ${WEBROOT}"
  mkdir -p "${WEBROOT}"

  if [[ ! "${SYNC_EXISTING}" =~ ^[Yy]$ ]]; then
    info "Синхронизацию источника пропускаю — оставляю файлы как есть."
  else
    case "${SRC_MODE}" in
      0)
        # локальные файлы рядом со скриптом
        [[ -f "./index.html" ]] && cp -f "./index.html" "${WEBROOT}/" || true
        [[ -f "./data.json"  ]] && cp -f "./data.json"  "${WEBROOT}/" || true
        [[ -f "${WEBROOT}/index.html" ]] || {
          info "Создаю базовый index.html"; cat > "${WEBROOT}/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>Сайт развернут</title>
<main style="max-width:800px;margin:4rem auto;font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif">
<h1>Готово ✔</h1><p>Этот сайт обслуживается Caddy. Данные берутся из <code>data.json</code>.</p>
<pre id="data" style="padding:1rem;border:1px solid #ddd;border-radius:8px"></pre>
<script>
fetch('/data.json',{cache:'no-store'})
.then(r=>r.json()).then(j=>{document.querySelector('#data').textContent=JSON.stringify(j,null,2)})
.catch(e=>{document.querySelector('#data').textContent='Ошибка чтения data.json: '+e});
</script>
</main>
HTML
        }
        validate_or_create_json "${WEBROOT}/data.json"
        ;;
      1)
        # пустой шаблон
        [[ -f "${WEBROOT}/index.html" ]] || cat > "${WEBROOT}/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>Сайт развернут</title>
<main style="max-width:800px;margin:4rem auto;font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif">
<h1>Готово ✔</h1><p>Этот сайт обслуживается Caddy. Данные берутся из <code>data.json</code>.</p>
<pre id="data" style="padding:1rem;border:1px solid #ddd;border-radius:8px"></pre>
<script>
fetch('/data.json',{cache:'no-store'})
.then(r=>r.json()).then(j=>{document.querySelector('#data').textContent=JSON.stringify(j,null,2)})
.catch(e=>{document.querySelector('#data').textContent='Ошибка чтения data.json: '+e});
</script>
</main>
HTML
        validate_or_create_json "${WEBROOT}/data.json"
        ;;
      2)
        rsync -a --delete "${LOCAL_PATH}/" "${WEBROOT}/"
        [[ -f "${WEBROOT}/data.json" ]] || validate_or_create_json "${WEBROOT}/data.json"
        ;;
      3)
        tmp="$(mktemp -d)"; git clone --depth=1 ${GIT_BRANCH:+--branch "${GIT_BRANCH}"} "${GIT_URL}" "${tmp}/repo"
        rsync -a --delete "${tmp}/repo/" "${WEBROOT}/"; rm -rf "${tmp}"
        [[ -f "${WEBROOT}/data.json" ]] || validate_or_create_json "${WEBROOT}/data.json"
        ;;
      4)
        tmp="$(mktemp -d)"; (cd "${tmp}" && curl -fLo archive "$(printf "%s" "${ARCH_URL}")")
        mkdir -p "${tmp}/unzipped"
        if file "${tmp}/archive" | grep -qi zip; then unzip -q "${tmp}/archive" -d "${tmp}/unzipped"
        else tar -xpf "${tmp}/archive" -C "${tmp}/unzipped" || tar -xzpf "${tmp}/archive" -C "${tmp}/unzipped" || tar -xJpf "${tmp}/archive" -C "${tmp}/unzipped"; fi
        top="$(find "${tmp}/unzipped" -mindepth 1 -maxdepth 1 -type d -o -type f | head -n1)"
        if [[ -d "${top}" ]]; then rsync -a --delete "${top}/" "${WEBROOT}/"; else rsync -a --delete "${tmp}/unzipped/" "${WEBROOT}/"; fi
        rm -rf "${tmp}"
        [[ -f "${WEBROOT}/data.json" ]] || validate_or_create_json "${WEBROOT}/data.json"
        ;;
    esac
  fi

  # права
  id -u filebrowser >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin filebrowser
  chown -R filebrowser:filebrowser "${WEBROOT}"
  find "${WEBROOT}" -type d -exec chmod 755 {} \; ; find "${WEBROOT}" -type f -exec chmod 644 {} \;

  # подсказки по вашему index.html (линты)
  lint_index_html "${WEBROOT}/index.html"
}

### ───────── File Browser ─────────
install_or_update_filebrowser(){
  info "Установка/проверка File Browser…"
  if ! command -v filebrowser >/dev/null 2>&1; then
    curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash
  else
    info "File Browser уже установлен."
  fi
  mkdir -p /var/lib/filebrowser
  [[ -f /var/lib/filebrowser/filebrowser.db ]] || { touch /var/lib/filebrowser/filebrowser.db; chown -R filebrowser:filebrowser /var/lib/filebrowser; }

  # создаём админа, если его нет
  if ! /usr/local/bin/filebrowser users find "${FB_ADMIN_USER}" --database /var/lib/filebrowser/filebrowser.db >/dev/null 2>&1; then
    /usr/local/bin/filebrowser users add "${FB_ADMIN_USER}" "${FB_ADMIN_PASS}" --perm.admin --database /var/lib/filebrowser/filebrowser.db
  else
    info "Пользователь ${FB_ADMIN_USER} уже существует — пропускаю."
  fi

  # актуализируем systemd-юнит при отличиях
  local unit=/etc/systemd/system/filebrowser.service
  local tmpu; tmpu="$(mktemp)"
  cat > "${tmpu}" <<SERVICE
[Unit]
Description=File Browser
After=network.target

[Service]
User=filebrowser
Group=filebrowser
ExecStart=/usr/local/bin/filebrowser \\
  -r ${WEBROOT} \\
  -a 127.0.0.1 -p 8080 \\
  -d /var/lib/filebrowser/filebrowser.db
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE
  if [[ ! -f "${unit}" ]] || ! cmp -s "${tmpu}" "${unit}"; then
    [[ -f "${unit}" ]] && cp "${unit}" "${unit}.$(timestamp).bak"
    mv "${tmpu}" "${unit}"
    systemctl daemon-reload
  else
    rm -f "${tmpu}"
  fi
  ensure_service_enabled_started filebrowser
}

### ───────── Caddy / Cloudflare ─────────
ensure_caddy_with_cloudflare_if_needed(){
  if [[ "${CF_MODE}" != "2" ]]; then info "DNS-01 плагин не нужен."; return 0; fi
  info "Проверяю наличие модуля dns.providers.cloudflare…"
  if caddy list-modules --packages 2>/dev/null | grep -q 'dns.providers.cloudflare'; then
    info "Плагин уже есть."
  else
    info "Пытаюсь добавить плагин: caddy add-package github.com/caddy-dns/cloudflare"
    if caddy add-package github.com/caddy-dns/cloudflare; then
      info "Плагин добавлен."
    else
      warn "add-package не сработал — собираю через xcaddy."
      ensure_pkgs golang-go
      command -v xcaddy >/dev/null 2>&1 || curl -fsSL https://raw.githubusercontent.com/caddyserver/xcaddy/master/install.sh | bash -s --
      tmpb="$(mktemp -d)"; (cd "${tmpb}" && /usr/local/bin/xcaddy build --with github.com/caddy-dns/cloudflare)
      [[ -x "${tmpb}/caddy" ]] || { err "Сборка caddy с cloudflare плагином не удалась"; }
      cp /usr/bin/caddy "/usr/bin/caddy.$(timestamp).bak" || true
      install -m 0755 "${tmpb}/caddy" /usr/bin/caddy
      rm -rf "${tmpb}"
    fi
  fi

  mkdir -p /etc/caddy
  local envfile="/etc/caddy/cloudflare.env"
  [[ -f "${envfile}" ]] || { printf "CLOUDFLARE_API_TOKEN=%s\n" "${CF_API_TOKEN}" > "${envfile}"; chmod 600 "${envfile}"; }
  mkdir -p /etc/systemd/system/caddy.service.d
  local dropin="/etc/systemd/system/caddy.service.d/cloudflare.conf"
  [[ -f "${dropin}" ]] || { cat > "${dropin}" <<'EOF'
[Service]
EnvironmentFile=/etc/caddy/cloudflare.env
EOF
  systemctl daemon-reload; }
}

write_caddyfile(){
  info "Генерирую Caddyfile…"
  local GLOBAL=""; [[ -n "${ACME_EMAIL:-}" ]] && GLOBAL=$'{\n\temail '"${ACME_EMAIL}"$'\n}\n\n'
  local WWW_BLOCK=""; if [[ "${WWW_REDIRECT}" =~ ^[Yy]$ ]]; then WWW_BLOCK=$"www.${DOMAIN} {\n    redir https://${DOMAIN}{uri}\n}\n\n"; fi
  local SPA=''; [[ "${SPA_MODE}" =~ ^[Yy]$ ]] && SPA=$'    try_files {path} /index.html\n'
  local JSON_NOCACHE=$'    @json path /data.json\n    header @json Cache-Control "no-store"\n'
  local TLS_MAIN=""; local TLS_EDIT=""
  if [[ "${CF_MODE}" == "2" ]]; then
    TLS_MAIN=$'    tls {\n        dns cloudflare {env.CLOUDFLARE_API_TOKEN}\n    }\n'
    TLS_EDIT=$'    tls {\n        dns cloudflare {env.CLOUDFLARE_API_TOKEN}\n    }\n'
  fi
  local HASH=""; local EDIT_AUTH=""
  if [[ "${BA_ENABLE}" =~ ^[Yy]$ ]]; then
    HASH="$(caddy hash-password --plaintext "${BA_PASS}")"
    EDIT_AUTH=$"    basicauth {\n        ${BA_USER} ${HASH}\n    }\n"
  fi

  local MAIN_BLOCK=$"${DOMAIN} {\n    root * ${WEBROOT}\n    encode zstd gzip\n${JSON_NOCACHE}    file_server\n${SPA}${TLS_MAIN}}\n"
  local EDIT_BLOCK=$"${EDIT_SUB} {\n${EDIT_AUTH}    reverse_proxy 127.0.0.1:8080\n${TLS_EDIT}}\n"

  local tmpcf; tmpcf="$(mktemp)"
  printf "%b" "${GLOBAL}${WWW_BLOCK}${MAIN_BLOCK}\n${EDIT_BLOCK}" > "${tmpcf}"

  local cf="/etc/caddy/Caddyfile"
  if [[ -f "${cf}" ]] && ! cmp -s "${tmpcf}" "${cf}"; then cp "${cf}" "${cf}.$(timestamp).bak"; fi
  mv "${tmpcf}" "${cf}"
  caddy validate --config "${cf}"
  systemctl reload caddy
}

### ───────── Бэкап data.json ─────────
setup_datajson_backup(){
  info "Настраиваю ежедневный бэкап data.json…"
  local backup_dir="/var/backups/${DOMAIN}"; mkdir -p "${backup_dir}"
  local script="/usr/local/bin/backup-datajson-${DOMAIN}.sh"
  cat > "${script}" <<SCRIPT
#!/usr/bin/env bash
set -Eeuo pipefail
src="${WEBROOT}/data.json"
dst_dir="${backup_dir}"
[[ -f "\$src" ]] || exit 0
mkdir -p "\$dst_dir"
cp -f "\$src" "\$dst_dir/data.json.\$(date +%Y%m%d-%H%M%S).bak"
# хранить последние 60 копий
ls -1t "\$dst_dir"/data.json.*.bak 2>/dev/null | tail -n +61 | xargs -r rm -f --
SCRIPT
  chmod +x "${script}"

  cat > /etc/systemd/system/datajson-backup-${DOMAIN}.service <<SERVICE
[Unit]
Description=Backup data.json for ${DOMAIN}

[Service]
Type=oneshot
ExecStart=${script}
SERVICE

  cat > /etc/systemd/system/datajson-backup-${DOMAIN}.timer <<TIMER
[Unit]
Description=Daily data.json backup for ${DOMAIN}

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
TIMER

  systemctl daemon-reload
  systemctl enable --now datajson-backup-${DOMAIN}.timer
}

### ───────── main ─────────
require_root
check_os
prompt_inputs
ensure_ports_free
apt_setup
firewall_setup
dns_hint
prepare_webroot
install_or_update_filebrowser
ensure_caddy_with_cloudflare_if_needed
write_caddyfile
setup_datajson_backup

info "Готово! Проверьте:"
echo "  Сайт:              https://${DOMAIN}"
[[ "${WWW_REDIRECT}" =~ ^[Yy]$ ]] && echo "  Редирект:          https://www.${DOMAIN} → https://${DOMAIN}"
echo "  Файловый менеджер: https://${EDIT_SUB} (логин: ${FB_ADMIN_USER})"
[[ "${BA_ENABLE}" =~ ^[Yy]$ ]] && echo "  BasicAuth:         логин ${BA_USER} (доп. защита)"
echo "  Файлы сайта:       ${WEBROOT}"
echo "  Бэкапы JSON:       /var/backups/${DOMAIN}/"
[[ "${CF_MODE}" == "2" ]] && echo "  DNS-01 Cloudflare: включён (прокси-режим в Cloudflare поддерживается)"
echo
echo "Примечание: Cache-Control: no-store для /data.json настроен — изменения видны сразу."
