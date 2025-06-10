# vsQUIC

клонируем репозиторий
``` bash
git clone https://github.com/UserAccountNotFound/vsQUIC_v2.git /opt/vsQUIC
```
обновляем пакетную базу дистрибутива и сразу обновсляем операционную систему
```bash
apt update && apt upgrade -y
```
устанавливаем Python и его пакетный менеджер
```bash
apt install python3 python-pip
```
переходим в целевую папку
``` bash
cd /opt/vsQUIC
```
# запуск

  переходим в соответствующую папку: Server или Client
``` bash
cd ./server
```
создаем виртуальное окружение Python
``` bash
python -m venv venv
```
переходи в виртуальное окружение
``` bash
source ./venv/bin/activate
```
устанавливаем зависимости
``` bash
pip install -r ./requirements.txt
```
запускаем .....
```bash
python ./quic-srv-.....py
```

