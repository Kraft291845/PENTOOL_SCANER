## PENTOOL_SCANER - легковесный сканер портов сайта написанный на Python3 с анализом уязвимостей ##



usage: main.py [-h] --target TARGET [--ports PORTS] [--mode {black,gray,white}] [--creds CREDS] [--output OUTPUT]


--target URL сайта

--ports порты для сканирования

--mode режим сканирования

--creds данные для входа (не обязательно)

--output файл_отчета.html


Пример использования: python3 main.py --target https://testURL.com --ports 80,22,443 --mode white --output file.html
