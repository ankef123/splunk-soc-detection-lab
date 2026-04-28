Сгенерируем безвредную encoded powershell команду (whoami), для того, чтобы проверить как sysmon + конфиг определят атаку.
# 1. Атака
    powershell.exe -enc dwBoAG8AYQBtAGkA

![encoded_powershell_command](screenshots/image.png)

# 2. Источник логов (Data Source)
Sysmon (EventID 1 - ProcessCreate)

Ключевые поля:
ParentCommandLine
ParentImage
Image
CommandLine

# 3. Detection
    index=windows EventCode=1 
    (ParentCommandLine="*-enc*" OR CommandLine="*-enc*")

![screen_of_detection](screenshots/image-1.png)

![detection_with_commandline](screenshots/image-2.png)

# 4. alert settings
![alert1](screenshots/image-3.png)
![alert2](screenshots/image-4.png)

# 5. triggered alert
![alert](screenshots/image-5.png)

# 6. Investigation
Основные поля, которые мы получаем сразу:
Image: whoami.exe
CommandLine: whoami.exe
ParentImage: powershell.exe
ParentCommandLine: powershell.exe -enc dwBoAG8AYQBtAGkA
User: LAB\Администратор

Делаем первичный вывод:
1) Запущена команда whoami, через encoded PowerShell

Ещё полезные поля:
ProcessId: 8508
ParentProcessId: 2420

Теперь выполним:
    index=windows EventCode=1 ProcessId=8508 OR ProcessId=2420
    | table _time Image CommandLine ParentImage ParentCommandLine

![investigation spl](screenshots/image-6.png)

