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
        logging.FileHandler('/opt/quic_server.log'),
        logging.StreamHandler()
    ]
)

class VulnerableQuicServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._total_data_received = 0
        self._connection_start = datetime.now()
        self._client_address = None
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
                logging.debug(f"Получен датаграмма размером {len(event.data)} байт")

            if self._http is None:
                return

            for http_event in self._http.handle_event(event):
                if isinstance(http_event, HeadersReceived):
                    self._handle_headers(http_event)

                elif isinstance(http_event, DataReceived):
                    self._handle_data(http_event)

        except Exception as e:
            logging.error(f"Ошибка обработки события: {str(e)}", exc_info=True)

    def _handle_headers(self, event):
        logging.warning("\n=== Уязвимость: Принятие непроверенных заголовков ===")
        headers_info = []
        for name, value in event.headers:
            try:
                header_str = f"{name.decode(errors='replace')}: {value.decode(errors='replace')}"
                headers_info.append(header_str)

                if name == b"x-malicious":
                    logging.warning("!!! Обнаружен вредоносный заголовок x-malicious !!!")

            except Exception as e:
                logging.warning(f"  [бинарные данные]: {value[:20]!r}...")

        logging.info(f"Получено {len(event.headers)} заголовков:\n" + "\n".join(headers_info))
        self._send_response(event.stream_id)

    def _handle_data(self, event):
        self._total_data_received += len(event.data)
        logging.warning(f"\n=== Уязвимость: Получено {len(event.data)} байт данных (всего: {self._total_data_received}) ===")

        try:
            sample = event.data[:100].decode('utf-8', errors='replace')
            logging.info(f"Начало данных: {sample!r}")
        except:
            logging.info("Не удалось декодировать данные")

        if self._total_data_received > 100000:
            logging.error("!!! ПРЕДУПРЕЖДЕНИЕ: Получено более 100KB данных - возможная DoS атака !!!")

    def _send_response(self, stream_id):
        response_headers = [
            (b":status", b"200"),
            (b"content-type", b"text/plain"),
            (b"x-server-info", b"VulnerableQUIC/1.3"),
            (b"x-vulnerable", b"true")
        ]

        response_data = b"Request processed successfully\n"

        logging.warning("\n=== Уязвимость: Отправка ответа с серверной информацией ===")
        try:
            self._http.send_headers(stream_id=stream_id, headers=response_headers)
            self._http.send_data(stream_id=stream_id, data=response_data, end_stream=True)
        except Exception as e:
            logging.error(f"Ошибка отправки ответа: {str(e)}")

async def run_server():
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
        max_datagram_size=1350,
        idle_timeout=30,
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
            create_protocol=VulnerableQuicServerProtocol,
            retry=True,
        )
        logging.info("\nСервер успешно запущен на 0.0.0.0:4433")
        logging.warning("Демонстрируемые уязвимости:")
        logging.warning("- Принимает любые заголовки без проверки")
        logging.warning("- Нет ограничений на размер данных")
        logging.warning("- Раскрывает информацию о сервере")
        logging.warning("- Уязвим к DoS атакам")

        await asyncio.Future()  # Бесконечное ожидание

    except Exception as e:
        logging.critical(f"\n!!! ОШИБКА ПРИ ЗАПУСКЕ СЕРВЕРА: {e} !!!")
        if "Address already in use" in str(e):
            logging.info("Порт 4433 уже занят. Закройте другие серверы или используйте другой порт.")

if __name__ == "__main__":
    print("Запуск уязвимого QUIC/HTTP3 сервера...")
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        print("\nСервер остановлен по запросу пользователя")
    except Exception as e:
        print(f"\nКритическая ошибка: {str(e)}")
