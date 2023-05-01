import re

# создаем словарь для хранения информации об ip-адресах атакующих и количестве запросов
attackers_count = {}

# открываем файл журнала доступа
with open("access.log", "r") as f:
    # читаем файл построчно
    for line in f:
        # разбиваем строку на части по пробелу
        parts = line.split()

        # проверяем, соответствует ли строка формату логов Apache
        if len(parts) >= 7:
            # извлекаем ip-адрес атакующего
            ip = parts[0]

            # извлекаем метод запроса
            method = parts[5]

            # извлекаем код ответа сервера
            status = parts[6]

            # проверяем, является ли ip-адрес атакующего новым
            if ip not in attackers_count:
                attackers_count[ip] = 1
            else:
                attackers_count[ip] += 1

            # проверяем, является ли полученный код ответа сервера признаком атаки
            if re.match(r'^4\d\d|5\d\d$', status):
                # записываем полный лог атаки
                print(line)

            # проверяем, является ли полученный метод запроса признаком атаки
            if method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                # записываем полный лог атаки
                print(line)

# выводим список ip-адресов атакующих и количества запросов
for ip, count in attackers_count.items():
    if count > 100:
        print(f"{ip}: {count} requests")