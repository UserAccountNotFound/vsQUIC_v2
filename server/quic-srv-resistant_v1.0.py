import asyncio
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived, DatagramReceived
from pathlib import Path

class VulnerableQuicServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._total_data_received = 0
        self._connection_checked = False  # Флаг проверки соединения

        # Ограничения безопасности
        self.MAX_HEADER_NAME_LENGTH = 128
        self.MAX_HEADER_VALUE_LENGTH = 4096
        self.MAX_TOTAL_HEADERS_SIZE = 16384
        self.MAX_REQUEST_SIZE = 1024 * 1024

        # Минимальная поддерживаемая версия QUIC
        self.MIN_SUPPORTED_QUIC_VERSION = 0x00000001  # Пример версии, укажите актуальную

        # Белый список разрешённых заголовков
        self.ALLOWED_HEADERS = {
            b'host',
            b'user-agent',
            b'accept',
            b'accept-language',
            b'accept-encoding',
            b'content-type',
            b'content-length',
            b'referer',
            b'connection',
            b'cache-control',
            b'upgrade-insecure-requests',
            b'method',
            b'path',
            b'authority',
            b'scheme',
            b'content-type',
            b'content-length',
            b'cookie',
            b'status',
            b'authorization',
            b'date',
            b'server',
            b'set-cookie',
            b'location',
            b'alt-svc',
            b'early-date',
            b'priority',
        }

        # Обязательные заголовки
        self.REQUIRED_HEADERS = {
            b':method': lambda v: v.strip() != b'',
            b':path': lambda v: v.strip() != b'',
            b':scheme': lambda v: v.strip() != b'',
            b':authority': lambda v: v.strip() != b'',
        }

    def quic_event_received(self, event):
        # Первоначальная проверка версии протокола
        if not self._connection_checked:
            self._connection_checked = True
            if not self.check_protocol_version():
                return  # Соединение будет закрыто

        if self._http is None:
            self._http = H3Connection(self._quic)

        if isinstance(event, HeadersReceived):
            print("\n=== Получены заголовки ===")
            if not self.validate_headers(event.headers):
                return
            self.handle_request(event)

        elif isinstance(event, DataReceived):
            self._total_data_received += len(event.data)
            if self._total_data_received > self.MAX_REQUEST_SIZE:
                print(f"!!! ОТКЛОНЕНО: Слишком большой запрос ({self._total_data_received} байт)")
                self.send_error_response(
                    event.stream_id,
                    413,
                    f"Размер запроса превышает максимум {self.MAX_REQUEST_SIZE} байт"
                )
                return

            print(f"\nПолучено {len(event.data)} байт (всего: {self._total_data_received})")
            try:
                print(f"Предпросмотр данных: {event.data[:100]!r}")
            except:
                print("Не удалось декодировать данные")

    def check_protocol_version(self):
        """Проверка версии протокола QUIC"""
        quic_version = self._quic._version
        if quic_version < self.MIN_SUPPORTED_QUIC_VERSION:
            print(f"!!! Устаревшая версия протокола: {hex(quic_version)}")

            # Отправка сообщения о необходимости обновления
            message = (
                "Ваша версия QUIC устарела. Пожалуйста, обновите клиент "
                f"до версии {hex(self.MIN_SUPPORTED_QUIC_VERSION)} или новее."
            )

            # Если HTTP/3 уже инициализирован, отправляем через него
            if self._http is not None:
                response_headers = [
                    (b":status", b"426"),
                    (b"content-type", b"text/plain"),
                    (b"upgrade", f"QUIC;version={hex(self.MIN_SUPPORTED_QUIC_VERSION)}".encode()),
                ]
                self._http.send_headers(stream_id=0, headers=response_headers)
                self._http.send_data(stream_id=0, data=message.encode(), end_stream=True)
            else:
                # Иначе отправляем как DATAGRAM
                self._quic.send_datagram_frame(message.encode())

            # Закрываем соединение с указанием кода ошибки
            self._quic.close(error_code=0x010C, reason_phrase=message.encode())
            return False

        return True

    def validate_headers(self, headers):
        """Проверка заголовков"""
        total_size = 0
        pseudo_headers = set()
        found_headers = set()

        if not headers:
            print("!!! ОТКЛОНЕНО: Заголовки отсутствуют")
            self.send_error_response(0, 400, "Заголовки запроса отсутствуют")
            return False

        stream_id = headers[0][0]

        for name, value in headers:
            try:
                name_lower = name.lower()
                total_size += len(name) + len(value)

                if not name.strip():
                    print("!!! ОТКЛОНЕНО: Пустое имя заголовка")
                    self.send_error_response(stream_id, 400, "Имя заголовка не может быть пустым")
                    return False

                if len(name) > self.MAX_HEADER_NAME_LENGTH:
                    print(f"!!! ОТКЛОНЕНО: Слишком длинное имя заголовка: {len(name)} байт")
                    self.send_error_response(
                        stream_id,
                        400,
                        f"Имя заголовка превышает {self.MAX_HEADER_NAME_LENGTH} байт"
                    )
                    return False

                if len(value) > self.MAX_HEADER_VALUE_LENGTH:
                    print(f"!!! ОТКЛОНЕНО: Слишком длинное значение заголовка: {len(value)} байт")
                    self.send_error_response(
                        stream_id,
                        400,
                        f"Значение заголовка превышает {self.MAX_HEADER_VALUE_LENGTH} байт"
                    )
                    return False

                if name.startswith(b':'):
                    if name in pseudo_headers:
                        print(f"!!! ОТКЛОНЕНО: Дублирующийся псевдо-заголовок: {name.decode()}")
                        self.send_error_response(stream_id, 400, "Дублирующийся псевдо-заголовок")
                        return False
                    pseudo_headers.add(name)

                    if name in self.REQUIRED_HEADERS:
                        found_headers.add(name)
                        if not self.REQUIRED_HEADERS[name](value):
                            print(f"!!! ОТКЛОНЕНО: Обязательный заголовок {name.decode()} не содержит данных")
                            self.send_error_response(
                                stream_id,
                                400,
                                f"Обязательный заголовок {name.decode()} не содержит данных"
                            )
                            return False
                    continue

                if name_lower not in self.ALLOWED_HEADERS:
                    print(f"!!! ОТКЛОНЕНО: Неразрешённый заголовок: {name.decode()}")
                    self.send_error_response(
                        stream_id,
                        403,
                        f"Заголовок не разрешён: {name.decode()}"
                    )
                    return False

                print(f"  {name.decode()}: {value.decode()}")

            except UnicodeDecodeError:
                print(f"!!! ОТКЛОНЕНО: Неверная кодировка заголовка")
                self.send_error_response(stream_id, 400, "Неверная кодировка заголовка")
                return False

        if total_size > self.MAX_TOTAL_HEADERS_SIZE:
            print(f"!!! ОТКЛОНЕНО: Слишком большие заголовки: {total_size} байт")
            self.send_error_response(
                stream_id,
                400,
                f"Общий размер заголовков превышает {self.MAX_TOTAL_HEADERS_SIZE} байт"
            )
            return False

        missing_headers = set(self.REQUIRED_HEADERS.keys()) - found_headers
        if missing_headers:
            print(f"!!! ОТКЛОНЕНО: Отсутствуют обязательные заголовки: {', '.join(h.decode() for h in missing_headers)}")
            self.send_error_response(
                stream_id,
                400,
                f"Отсутствуют обязательные заголовки: {', '.join(h.decode() for h in missing_headers)}"
            )
            return False

        return True

    def send_error_response(self, stream_id, status_code, message):
        """Отправка ответа с ошибкой"""
        response_headers = [
            (b":status", str(status_code).encode()),
            (b"content-type", b"text/plain"),
        ]
        response_data = f"Ошибка: {message}\n".encode()

        self._http.send_headers(stream_id=stream_id, headers=response_headers)
        self._http.send_data(stream_id=stream_id, data=response_data, end_stream=True)

    def handle_request(self, event):
        """Обработка валидного запроса"""
        response_headers = [
            (b":status", b"200"),
            (b"content-type", b"text/plain"),
        ]
        response_data = b"Request processed successfully\n"

        print("\n=== Отправка ответа ===")
        self._http.send_headers(stream_id=event.stream_id, headers=response_headers)
        self._http.send_data(stream_id=event.stream_id, data=response_data, end_stream=True)

async def run_server():
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
    )

    cert_path = Path("/opt/ENV/cert-srv.pem")
    key_path = Path("/opt/ENV/key-srv.pem")

    if not cert_path.exists() or not key_path.exists():
        print("\n!!! ОШИБКА: Файлы сертификатов не найдены !!!")
        print(f"Ожидаемые пути:\n- Сертификат: {cert_path}\n- Ключ: {key_path}")
        return

    configuration.load_cert_chain(cert_path, key_path)
    configuration.verify_peer = False

    try:
        server = await serve(
            host="0.0.0.0",
            port=4433,
            configuration=configuration,
            create_protocol=VulnerableQuicServerProtocol,
            retry=True,
        )

        print("\nСервер запущен на 0.0.0.0:4433")
        print(f"Минимальная поддерживаемая версия QUIC: {hex(VulnerableQuicServerProtocol.MIN_SUPPORTED_QUIC_VERSION)}")
        print("Ограничения безопасности:")
        print(f"- Макс. длина имени заголовка: {VulnerableQuicServerProtocol.MAX_HEADER_NAME_LENGTH}")
        print(f"- Макс. длина значения заголовка: {VulnerableQuicServerProtocol.MAX_HEADER_VALUE_LENGTH}")
        print(f"- Макс. общий размер заголовков: {VulnerableQuicServerProtocol.MAX_TOTAL_HEADERS_SIZE}")
        print(f"- Макс. размер запроса: {VulnerableQuicServerProtocol.MAX_REQUEST_SIZE}")
        print(f"- Разрешённые заголовки: {sorted([h.decode() for h in VulnerableQuicServerProtocol.ALLOWED_HEADERS])}")
        print(f"- Обязательные заголовки: {sorted([h.decode() for h in VulnerableQuicServerProtocol.REQUIRED_HEADERS.keys()])}")

        await asyncio.Future()

    except Exception as e:
        print(f"\n!!! ОШИБКА СЕРВЕРА: {e} !!!")

if __name__ == "__main__":
    print("Запуск QUIC/HTTP3 сервера с проверкой версии протокола...")
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        print("\nСервер остановлен пользователем")
