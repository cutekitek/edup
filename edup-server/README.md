# edup-server

Разовый Linux-загрузчик. После `up` он выходит; обработка трафика остаётся в
XDP. Нужны root, bpffs и поддержка XDP BPF links целевым ядром/драйвером.

## Сборка

```sh
rustup toolchain install nightly-2026-09-26 --profile minimal --component rust-src
# Установить официальный bpf-linker 0.11.1 в PATH.
cargo build --locked --release -p edup-server
```

`build.rs` вызывает `aya_build::build_ebpf`; ELF встраивается в бинарник.
На сервере для запуска не нужны Rust, исходники или отдельный ELF.
На Windows доступны `check` и тесты конфигурации; работа с BPF — только Linux.
`AYA_BUILD_SKIP` не использовать для чистой сборки: без ELF в OUT_DIR собрать
рабочий загрузчик нельзя.

## Конфигурация и запуск

Основа — [`config/server.example.toml`](../config/server.example.toml).
Заменить внешние IP, интерфейс, пароль и ID пользователей. Режим `driver`
означает native XDP; `skb` выбирается явно для диагностики. Автоматического
перехода к generic XDP нет. Поддерживается Ethernet без VLAN.

```sh
sudo install -d -m 700 /etc/edup
sudo install -m 600 config/server.example.toml /etc/edup/server.toml
# Отредактировать /etc/edup/server.toml перед запуском.
sudo install -m 755 target/release/edup-server /usr/local/sbin/edup-server
edup-server --config config/server.example.toml check

# Если bpffs ещё не смонтирован:
sudo mount -t bpf -o mode=700 bpf /sys/fs/bpf
sudo edup-server up
sudo edup-server stats
sudo edup-server users
sudo edup-server reload
sudo edup-server down
```

`--config` и `--pin-path` — глобальные опции (по умолчанию
`/etc/edup/server.toml` и `/sys/fs/bpf/edup`). `down`, `stats`, `users` не читают
TOML: они работают с текущим закреплённым экземпляром, даже если конфиг удалён.
`check` проверяет синтаксис, типы, неизвестные поля, адреса, сеть, ID, порты и MTU
без root; проверки окружения выполняются дополнительно при `up`/`reload`.

Туннельный адрес — `tunnel_net + id`. ID 0 запрещён; для /16 также запрещён
65535 (broadcast). Повторяющиеся ID запрещены. Пустой список пользователей
допустим. Сеть должна иметь нулевые host bits, префикс /1…/16 и не содержать
внешние адреса. `max_frame` — внешний IPv4 MTU; диапазон 612…1568 ограничен
внутренним MTU >=576 и лимитом XOR, а также MTU самого интерфейса.

NAT-диапазон должен быть полностью вне `net.ipv4.ip_local_port_range`.
Загрузчик проверяет это и текущие TCP/UDP-сокеты (IPv4/IPv6), но не меняет
sysctl, маршруты, firewall или адреса интерфейса. Указанные IP должны приходить
на выбранный интерфейс; схема XDP_TX предполагает один NIC и один шлюз.
Администратор должен исключить последующее явное занятие NAT-портов сервисами
хоста. В примере NAT 20000…29999 не пересекается с обычным 32768…60999.

## Срок жизни и reload

`up` сначала создаёт и заполняет карты, проверяет программу в ядре, закрепляет
новое поколение, затем прикрепляет и закрепляет XDP-link. Занятый XDP-слот
вызывает ошибку: загрузчик не заменяет чужую программу. Повторный `up` также
вызывает ошибку; для очистки неполного запуска предусмотрен `down`.

`reload` готовит отдельное поколение с новой конфигурацией и выполняет
атомарный `BPF_LINK_UPDATE` существующего link. До переключения любая ошибка
оставляет прежнее поколение активным. **Любой reload сбрасывает NAT, endpoints
и счётчики, поэтому прерывает текущие соединения.** Клиенты снова объявляют
endpoint следующим DATA/KEEPALIVE. Смена интерфейса или режима требует `down/up`.

В bpffs используется структура:

```text
/sys/fs/bpf/edup/
  link
  gen_<program-id>_<ifindex>_<driver|skb>/
    program
    CONFIG
    USERS
    NAT_OUT
    NAT_IN
    STATS
```

Активное поколение определяется по program ID закреплённого link, без
отдельного файла-указателя. После переключения старые pins удаляются. При
аварийном завершении между шагами могут остаться лишние поколения; успешный
`reload` либо `down` убирает их. `down` повторяем и удаляет только известные pins,
отказываясь от очистки каталогов с неизвестными файлами. Пути с symlink и
каталоги, доступные для записи другим пользователям, не принимаются.
Команды сериализуются через root-owned `/run/edup-loader.lock`; файл lock
намеренно остаётся после выхода. Счётчики/endpoint читаются во время обработки
пакетов и не представляют атомарный снимок всех CPU.

## systemd

```sh
sudo install -m 644 deploy/edup-server.service deploy/edup-bpffs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now edup-server
# Применение конфигурации (со сбросом соединений):
sudo systemctl reload edup-server
sudo systemctl stop edup-server
```

Конфиг должен быть подготовлен до запуска. Зависимость `edup-bpffs.service`
монтирует bpffs, если `/sys/fs/bpf` ещё не является точкой монтирования;
существующее монтирование сохраняется. Юнит сервера `oneshot` с
`RemainAfterExit=yes`: работающего userspace-демона нет.

## Проверки

```sh
cargo test --locked -p edup-server
sh scripts/check-server.sh
```

Второй сценарий требует `unshare`, `ip`, `mount`, sudo/root. Он создаёт
изолированные mount/network namespaces, собственный bpffs и пару veth.
Проверяет native/generic attach, сохранение link после выхода загрузчика,
пакет KEEPALIVE через kernel test-run, карты и вывод CLI, отказ при занятом
XDP-слоте, ошибки конфигурации/окружения без изменения активного состояния,
атомарную замену поколений, сброс NAT и повторный `down`. Хостовые интерфейсы,
маршруты и bpffs не меняются. Производительность и XDP_TX через реальный NIC
этим сценарием не измеряются.
