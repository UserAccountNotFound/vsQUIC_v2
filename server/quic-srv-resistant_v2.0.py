import asyncio
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived, DatagramReceived
from aioquic.quic.events import ProtocolNegotiated, ConnectionTerminated
import os
from pathlib import Path
import logging
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('./quic_server.log'),
        logging.StreamHandler()
    ]
)

class SecureQuicServerProtocol(QuicConnectionProtocol):
    # Константы безопасности (уровень класса)
    MAX_HEADER_NAME_LENGTH = 128
    MAX_HEADER_VALUE_LENGTH = 4096
    MAX_TOTAL_HEADERS_SIZE = 16384
    MAX_REQUEST_SIZE = 1024 * 1024  # 1MB
    MAX_DATAGRAM_SIZE = 1350
    CONNECTION_IDLE_TIMEOUT = 30  # секунды
    
    # Минимальная поддерживаемая версия QUIC
    MIN_SUPPORTED_QUIC_VERSION = 0x00000001
    
    # Белый список разрешённых заголовков
    ALLOWED_HEADERS = {
        b'host', b'user-agent', b'accept', b'accept-language',
        b'accept-encoding', b'content-type', b'content-length',
        b'referer', b'connection', b'cache-control',
        b'upgrade-insecure-requests', b'method', b'path',
        b'authority', b'scheme', b'cookie', b'status',
        b'authorization', b'date', b'server', b'set-cookie',
        b'location', b'alt-svc', b'early-data', b'priority',
    }
    
    # Обязательные заголовки
    REQUIRED_HEADERS = {
        b':method': lambda v: v.strip() != b'',
        b':path': lambda v: v.strip() != b'',
        b':scheme': lambda v: v.strip() != b'',
        b':authority': lambda v: v.strip() != b'',
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._total_data_received = 0
        self._connection_start = datetime.now()
        self._client_address = None
        self._connection_checked = False
        logging.info("Новое подключение инициализировано")

    def quic_event_received(self, event):
        try:
            if isinstance(event, ProtocolNegotiated):
                self._client_address = self._quic._network_paths[0].addr
                logging.info(f"Подключение от {self._client_address}")
                if self._http is None:
                    self._http = H3Connection(self._quic)

            elif isinstance(event, ConnectionTerminated):
                duration = datetime.now() - self._connection_start
                logging.warning(f"Соединение разорвано: {event.error_code} (duration: {duration.total_seconds():.2f}s)")
                return

            elif isinstance(event, DatagramReceived):
                if len(event.data) > self.MAX_DATAGRAM_SIZE:
                    logging.warning(f"Датаграмма слишком большая: {len(event.data)} байт")
                    self._quic.close(error_code=0x010D, reason_phrase=b"Datagram too large")
                    return
                logging.debug(f"Получен датаграмма размером {len(event.data)} байт")

            if not self._connection_checked:
                self._connection_checked = True
                if not self._check_protocol_version():
                    return

            if self._http is None:
                return

            for http_event in self._http.handle_event(event):
                if isinstance(http_event, HeadersReceived):
                    if not self._validate_headers(http_event.headers):
                        return
                    self._handle_headers(http_event)

                elif isinstance(http_event, DataReceived):
                    self._handle_data(http_event)

        except Exception as e:
            logging.error(f"Ошибка обработки события: {str(e)}", exc_info=True)
            self._quic.close(error_code=0x0101, reason_phrase=b"Internal server error")

    def _check_protocol_version(self):
        """Проверка версии протокола QUIC"""
        quic_version = self._quic._version
        if quic_version < self.MIN_SUPPORTED_QUIC_VERSION:
            logging.warning(f"Устаревшая версия протокола: {hex(quic_version)}")
            message = (
                "Ваша версия QUIC устарела. Пожалуйста, обновите клиент "
                f"до версии {hex(self.MIN_SUPPORTED_QUIC_VERSION)} или новее."
            ).encode()

            if self._http is not None:
                response_headers = [
                    (b":status", b"426"),
                    (b"content-type", b"text/plain"),
                    (b"upgrade", f"QUIC;version={hex(self.MIN_SUPPORTED_QUIC_VERSION)}".encode()),
                ]
                self._http.send_headers(stream_id=0, headers=response_headers)
                self._http.send_data(stream_id=0, data=message, end_stream=True)
            else:
                self._quic.send_datagram_frame(message)

            self._quic.close(error_code=0x010C, reason_phrase=message)
            return False
        return True

    def _validate_headers(self, headers):
        """Проверка заголовков на соответствие требованиям безопасности"""
        if not headers:
            logging.error("Заголовки отсутствуют")
            self._send_error_response(0, 400, "Заголовки запроса отсутствуют")
            return False

        total_size = 0
        pseudo_headers = set()
        found_headers = set()
        stream_id = headers[0][0]

        for name, value in headers:
            try:
                name_lower = name.lower()
                total_size += len(name) + len(value)

                # Проверка длины имени и значения заголовка
                if len(name) > self.MAX_HEADER_NAME_LENGTH:
                    logging.warning(f"Слишком длинное имя заголовка: {len(name)} байт")
                    self._send_error_response(
                        stream_id,
                        400,
                        f"Имя заголовка превышает {self.MAX_HEADER_NAME_LENGTH} байт"
                    )
                    return False

                if len(value) > self.MAX_HEADER_VALUE_LENGTH:
                    logging.warning(f"Слишком длинное значение заголовка: {len(value)} байт")
                    self._send_error_response(
                        stream_id,
                        400,
                        f"Значение заголовка превышает {self.MAX_HEADER_VALUE_LENGTH} байт"
                    )
                    return False

                # Проверка псевдо-заголовков
                if name.startswith(b':'):
                    if name in pseudo_headers:
                        logging.warning(f"Дублирующийся псевдо-заголовок: {name.decode()}")
                        self._send_error_response(stream_id, 400, "Дублирующийся псевдо-заголовок")
                        return False
                    pseudo_headers.add(name)

                    if name in self.REQUIRED_HEADERS:
                        found_headers.add(name)
                        if not self.REQUIRED_HEADERS[name](value):
                            logging.warning(f"Обязательный заголовок {name.decode()} не содержит данных")
                            self._send_error_response(
                                stream_id,
                                400,
                                f"Обязательный заголовок {name.decode()} не содержит данных"
                            )
                            return False
                    continue

                # Проверка разрешённых заголовков
                if name_lower not in self.ALLOWED_HEADERS:
                    logging.warning(f"Неразрешённый заголовок: {name.decode()}")
                    self._send_error_response(
                        stream_id,
                        403,
                        f"Заголовок не разрешён: {name.decode()}"
                    )
                    return False

                logging.info(f"  {name.decode()}: {value.decode()}")

            except UnicodeDecodeError:
                logging.warning("Неверная кодировка заголовка")
                self._send_error_response(stream_id, 400, "Неверная кодировка заголовка")
                return False

        # Проверка общего размера заголовков
        if total_size > self.MAX_TOTAL_HEADERS_SIZE:
            logging.warning(f"Слишком большие заголовки: {total_size} байт")
            self._send_error_response(
                stream_id,
                400,
                f"Общий размер заголовков превышает {self.MAX_TOTAL_HEADERS_SIZE} байт"
            )
            return False

        # Проверка обязательных заголовков
        missing_headers = set(self.REQUIRED_HEADERS.keys()) - found_headers
        if missing_headers:
            logging.warning(f"Отсутствуют обязательные заголовки: {', '.join(h.decode() for h in missing_headers)}")
            self._send_error_response(
                stream_id,
                400,
                f"Отсутствуют обязательные заголовки: {', '.join(h.decode() for h in missing_headers)}"
            )
            return False

        return True

    def _handle_headers(self, event):
        """Обработка валидных заголовков"""
        logging.info(f"Получено {len(event.headers)} заголовков")
        self._send_response(event.stream_id)

    def _handle_data(self, event):
        """Обработка данных с проверкой размера"""
        self._total_data_received += len(event.data)
        
        if self._total_data_received > self.MAX_REQUEST_SIZE:
            logging.error(f"Превышен максимальный размер запроса: {self._total_data_received} байт")
            self._send_error_response(
                event.stream_id,
                413,
                f"Размер запроса превышает максимум {self.MAX_REQUEST_SIZE} байт"
            )
            return

        logging.info(f"Получено {len(event.data)} байт данных (всего: {self._total_data_received})")
        try:
            sample = event.data[:100].decode('utf-8', errors='replace')
            logging.debug(f"Начало данных: {sample!r}")
        except Exception:
            logging.debug("Не удалось декодировать данные")

    def _send_response(self, stream_id):
        """Отправка успешного ответа"""
        response_headers = [
            (b":status", b"200"),
            (b"content-type", b"text/plain"),
        ]
        response_data = b"Request processed successfully\n"

        try:
            self._http.send_headers(stream_id=stream_id, headers=response_headers)
            self._http.send_data(stream_id=stream_id, data=response_data, end_stream=True)
        except Exception as e:
            logging.error(f"Ошибка отправки ответа: {str(e)}")

    def _send_error_response(self, stream_id, status_code, message):
        """Отправка ответа с ошибкой"""
        response_headers = [
            (b":status", str(status_code).encode()),
            (b"content-type", b"text/plain"),
        ]
        response_data = f"Ошибка: {message}\n".encode()

        try:
            self._http.send_headers(stream_id=stream_id, headers=response_headers)
            self._http.send_data(stream_id=stream_id, data=response_data, end_stream=True)
        except Exception as e:
            logging.error(f"Ошибка отправки ответа об ошибке: {str(e)}")

async def run_server():
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
        max_datagram_size=SecureQuicServerProtocol.MAX_DATAGRAM_SIZE,
        idle_timeout=SecureQuicServerProtocol.CONNECTION_IDLE_TIMEOUT,
    )

    # Проверка сертификатов
    cert_path = Path("./ENV/cert-srv.pem")
    key_path = Path("./ENV/key-srv.pem")

    if not cert_path.exists() or not key_path.exists():
        logging.critical("\n!!! ОШИБКА: Сертификаты не найдены !!!")
        logging.info(f"Ожидаемые пути:\n- Сертификат: {cert_path}\n- Ключ: {key_path}")
        logging.info("\nСоздайте тестовые сертификаты командой:")
        logging.info("openssl req -x509 -newkey rsa:4096 -keyout key-srv.pem -out cert-srv.pem -days 365 -nodes")
        return

    try:
        configuration.load_cert_chain(cert_path, key_path)
        logging.info("Сертификаты успешно загружены")
    except Exception as e:
        logging.critical(f"Ошибка загрузки сертификатов: {str(e)}")
        return

    configuration.verify_peer = False
    logging.warning("!!! ПРЕДУПРЕЖДЕНИЕ: Проверка сертификатов отключена (verify_peer=False) !!!")

    try:
        server = await serve(
            host="0.0.0.0",
            port=4433,
            configuration=configuration,
            create_protocol=SecureQuicServerProtocol,
            retry=True,
        )
        logging.info("\nСервер успешно запущен на 0.0.0.0:4433")
        logging.info("Настройки безопасности:")
        logging.info(f"- Макс. длина имени заголовка: {SecureQuicServerProtocol.MAX_HEADER_NAME_LENGTH}")
        logging.info(f"- Макс. длина значения заголовка: {SecureQuicServerProtocol.MAX_HEADER_VALUE_LENGTH}")
        logging.info(f"- Макс. общий размер заголовков: {SecureQuicServerProtocol.MAX_TOTAL_HEADERS_SIZE}")
        logging.info(f"- Макс. размер запроса: {SecureQuicServerProtocol.MAX_REQUEST_SIZE}")
        logging.info(f"- Минимальная версия QUIC: {hex(SecureQuicServerProtocol.MIN_SUPPORTED_QUIC_VERSION)}")

        await asyncio.Future()  # Бесконечное ожидание

    except Exception as e:
        logging.critical(f"\n!!! ОШИБКА ПРИ ЗАПУСКЕ СЕРВЕРА: {e} !!!")
        if "Address already in use" in str(e):
            logging.info("Порт 4433 уже занят. Закройте другие серверы или используйте другой порт.")

if __name__ == "__main__":
    print("Запуск защищённого QUIC/HTTP3 сервера...")
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        print("\nСервер остановлен по запросу пользователя")
    except Exception as e:
        print(f"\nКритическая ошибка: {str(e)}")