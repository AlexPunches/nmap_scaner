# Сканер портов по списку адресов

Не забываем установить и активировать окружение, установить зависимости
```bash
python3.10 -m venv venv
source venv/bin/activate
pip install -r ./requirements.txt
```

Чтобы запустить сканирование, нужно указать файлы с айпи-адресами и портами
```bash
python main.py data/ips.txt data/ports.txt
```