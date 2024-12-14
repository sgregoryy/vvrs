import os
import json
import time
import pprint
import tkinter as tk
from tkinter import ttk
from threading import Thread
from pathlib import Path
from blockchain import BlockChain  # Импортируем готовый класс
import datetime

# Глобальные переменные
accounts_folder = Path("blocks")
if not accounts_folder.exists():
    accounts_folder.mkdir()

pp = pprint.PrettyPrinter(indent=4)
is_solving_tasks = False
init = None


# Функция для сохранения хеш-значения в файл
def save_hash(username, password, user_hash):
    filename = accounts_folder / f"{username}.json"
    with open(filename, "w") as f:
        json.dump({"username": username, "password": password, "user_hash": user_hash}, f)


# Функция для обновления списка аккаунтов
def update_account_list():
    account_combobox['values'] = [f.stem for f in accounts_folder.glob("*.json")]


# Функция для выбора аккаунта
def on_account_select(event):
    selected_account = account_combobox.get()
    if selected_account:
        with open(accounts_folder / f"{selected_account}.json") as f:
            account_data = json.load(f)
            username_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
            username_entry.insert(0, account_data['username'])
            password_entry.insert(0, account_data['password'])
            from_hach_entry.delete(0, tk.END)
            from_hach_entry.insert(0, account_data['user_hash'])


# Функция для запуска постоянного получения задач
def start_task_processing():
    global is_solving_tasks
    while is_solving_tasks:
        time.sleep(2)
        result = init.get_chains()
        result = init.get_task().json()
        output_text.insert(tk.END, f'{str(datetime.datetime.now())} - Получены задачи: {pp.pformat(result)}\n')
        output_text.see(tk.END)

        if result['tasks']:
            for task in result['tasks']:
                task_id = task['id']
                data_json = task['data_json']
                hash_value = init.get_hash_object(json.dumps(data_json))
                result_hash = init.make_hash(hash_value)

                data = {
                    'type_task': 'BlockTaskUser_Solution',
                    'id': task_id,
                    'hash': result_hash
                }
                send_result = init.send_task(data)
                output_text.insert(tk.END, f'Решение отправлено: {pp.pformat(send_result.json())}\n')
                output_text.see(tk.END)


# Функция для запуска процесса решения задач
def start_solving_tasks():
    global is_solving_tasks
    if not is_solving_tasks:
        is_solving_tasks = True
        output_text.insert(tk.END, "Запуск решения задач...\n")
        thread = Thread(target=start_task_processing)
        thread.daemon = True
        thread.start()


# Функция для остановки процесса решения задач
def stop_solving_tasks():
    global is_solving_tasks
    is_solving_tasks = False
    output_text.insert(tk.END, "Остановка решения задач...\n")


# Функция авторизации
def login():
    global init
    username = username_entry.get()
    password = password_entry.get()

    # Создание объекта BlockChain
    init = BlockChain(username=username, password=password, base_url='https://b1.ahmetshin.com/restapi/')

    # Регистрация пользователя
    result = init.register()
    output_text.insert(tk.END, f'Авторизация: {pp.pformat(result.json())}\n')

    # Проверка баланса монет
    balance_result = init.check_coins()
    output_text.insert(tk.END, f'Баланс монет: {pp.pformat(balance_result.json())}\n')

    # Считываем и сохраняем хеш
    user_hash = init.hach_user
    save_hash(username, password, user_hash)

    # Заполняем поле from_hash
    from_hach_entry.delete(0, tk.END)
    from_hach_entry.insert(0, user_hash)

    # Автоматическая прокрутка вниз
    output_text.see(tk.END)


# Функция для отправки задачи
def send_task():
    from_hach = from_hach_entry.get()
    to_hach = to_hach_entry.get()
    count_coins = coins_entry.get()

    data = {
        'type_task': 'send_coins',
        'from_hach': from_hach,
        'to_hach': to_hach,
        'count_coins': int(count_coins)
    }
    result = init.send_task(data)
    output_text.insert(tk.END, f'Задача отправлена: {pp.pformat(result.json())}\n')
    output_text.see(tk.END)


# Функция для выхода из полноэкранного режима
def exit_fullscreen(event=None):
    root.attributes("-fullscreen", False)


# Функция для центрирования окна
def center_window(window, width=600, height=700):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")


# Создание основного окна приложения
root = tk.Tk()
root.title("Blockchain Client")
center_window(root)  # Центрирование окна
root.resizable(True, True)  # Запрет на изменение размеров окна

# Поля для авторизации
ttk.Label(root, text="Username:").grid(row=1, column=0, padx=10, pady=5)
username_entry = ttk.Entry(root)
username_entry.grid(row=1, column=1, padx=10, pady=5)

ttk.Label(root, text="Password:").grid(row=2, column=0, padx=10, pady=5)
password_entry = ttk.Entry(root, show="*")
password_entry.grid(row=2, column=1, padx=10, pady=5)

login_button = ttk.Button(root, text="Login", command=login)
login_button.grid(row=3, columnspan=2, padx=10, pady=5)

# Поля для ввода задачи
ttk.Label(root, text="From Hash:").grid(row=4, column=0, padx=10, pady=5)
from_hach_entry = ttk.Entry(root, width=50)
from_hach_entry.grid(row=4, column=1, padx=10, pady=5)

ttk.Label(root, text="To Hash:").grid(row=5, column=0, padx=10, pady=5)
to_hach_entry = ttk.Entry(root, width=50)
to_hach_entry.grid(row=5, column=1, padx=10, pady=5)

ttk.Label(root, text="Coins:").grid(row=6, column=0, padx=10, pady=5)
coins_entry = ttk.Entry(root)
coins_entry.grid(row=6, column=1, padx=10, pady=5)

send_task_button = ttk.Button(root, text="Send Task", command=send_task)
send_task_button.grid(row=7, columnspan=2, padx=10, pady=5)

# Кнопки для управления процессом решения задач
start_solving_button = ttk.Button(root, text="Start Solving Tasks", command=start_solving_tasks)
start_solving_button.grid(row=8, column=0, padx=10, pady=5)

stop_solving_button = ttk.Button(root, text="Stop Solving Tasks", command=stop_solving_tasks)
stop_solving_button.grid(row=8, column=1, padx=10, pady=5)

# Выпадающий список для аккаунтов
ttk.Label(root, text="Select Account:").grid(row=0, column=0, padx=10, pady=5)
account_combobox = ttk.Combobox(root, postcommand=update_account_list, width=18)
account_combobox.grid(row=0, column=1, padx=10, pady=5)
account_combobox.bind("<<ComboboxSelected>>", on_account_select)

# Поле для вывода результатов с ползунком
output_frame = ttk.Frame(root)
output_frame.grid(row=9, columnspan=2, padx=10, pady=5)

output_text = tk.Text(output_frame, height=24, width=70, wrap="word")
output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = ttk.Scrollbar(output_frame, command=output_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

output_text.config(yscrollcommand=scrollbar.set)

# Запуск основного цикла
root.mainloop()
