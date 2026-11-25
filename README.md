# portscan

Go-пакет для проверки доступности TCP-портов на одном или нескольких хостах.
TCP connect-сканирование без сторонних зависимостей.

```
go get github.com/DaniilGrigoritsa/portscan
```

Пакет не зависит от CLI, HTTP-фреймворков, баз данных и брокеров сообщений.
Тесты: `go test -race ./...`.

Либо через docker:
`docker build -t portscan-test .`
`docker run --rm portscan-test`

## 1. Как использовать

```go
scanner, err := portscan.New(
	portscan.WithConcurrency(100),
	portscan.WithConnectTimeout(500*time.Millisecond),
)
if err != nil {
	return err
}

results, err := scanner.Scan(
	ctx,
	[]string{"192.168.1.10", "2001:db8::1", "example.com"},
	portscan.Merge(portscan.Range(1, 1024), portscan.List(8080, 8443)),
)
if err != nil {
	return err
}

for r := range results {
	fmt.Printf("%s (%s):%d %s %v\n", r.Host, r.IP, r.Port, r.State, r.Duration)
}
```

## 2. Публичный API

### Сканер

| Сущность | Назначение |
|---|---|
| `New(opts ...Option) (*Scanner, error)` | создаёт сканер, проверяет опции |
| `(*Scanner).Scan(ctx, hosts []string, ports Ports) (<-chan Result, error)` | запускает сканирование и возвращает поток результатов |

`Scanner` неизменяем после создания: один экземпляр можно использовать из
нескольких горутин и вызывать `Scan` несколько раз, в том числе
параллельно. Нулевое значение `Scanner{}` тоже работает (настройки по
умолчанию).

### Опции

| Опция | По умолчанию | Описание |
|---|---|---|
| `WithConcurrency(n)` | 100 | максимум одновременных подключений одного вызова `Scan` |
| `WithConnectTimeout(d)` | 1s | таймаут одного подключения |
| `WithResolveTimeout(d)` | 5s | таймаут разрешения одного DNS-имени |
| `WithDialer(Dialer)` | `*net.Dialer` | свой способ подключения |
| `WithResolver(Resolver)` | `net.DefaultResolver` | свой DNS |

### Порты

`Ports` — неизменяемое множество портов. Создаётся функциями:

| Функция | Пример |
|---|---|
| `List(ports ...int)` | `List(22, 80, 443)` |
| `Range(first, last int)` | `Range(1, 1000)` |
| `Merge(sets ...Ports)` | `Merge(Range(1, 1024), List(8080))` |

Дополнительно: `Ports.Len()`, `Ports.String()` (формат `22,80,8000-8100`) и
`Ports.Err()`.
Ошибка сохраняется внутри `Ports`, проходит через `Merge` и возвращается из
`Scan`.

### Результат

```go
type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}
```

`State` (`StateOpen`, `StateClosed`, `StateTimeout`, `StateUnreachable`,
`StateCanceled`, `StateError`) имеет `String()` и `MarshalText()`.

## Как определяется состояние

Только по типам и кодам ошибок, никогда по тексту:

| Состояние | Условие |
|---|---|
| `open` | `DialContext` вернул `nil` |
| `closed` | `errors.Is(err, ECONNREFUSED)` |
| `unreachable` | `ENETUNREACH`, `EHOSTUNREACH`, `ENETDOWN`, `EHOSTDOWN` |
| `canceled` | `ctx` сканирования завершён или `errors.Is(err, context.Canceled)` |
| `timeout` | `context.DeadlineExceeded`, `os.ErrDeadlineExceeded` или `net.Error` с `Timeout() == true` |
| `error` | всё остальное |

На Windows дополнительно учитываются коды Winsock (`WSAECONNREFUSED` и др.), так как
они отличаются от POSIX-констант пакета `syscall`.
