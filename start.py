# app.py
from flask import Flask, render_template, request, jsonify, session
from blockchain import BlockChain
import json
from pathlib import Path
import datetime
import threading
import time
import logging
from datetime import timedelta
import json
import urllib3
    
from concurrent.futures import ProcessPoolExecutor, as_completed, ThreadPoolExecutor

# Отключаем предупреждения SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "your-secret-key-here"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=60)


ACCOUNTS_FOLDER = Path("blocks")
MESSAGES_FOLDER = Path("messages")
if not ACCOUNTS_FOLDER.exists():
    ACCOUNTS_FOLDER.mkdir()
if not MESSAGES_FOLDER.exists():
    MESSAGES_FOLDER.mkdir()


task_threads = {}
blockchain_instances = {}


@app.before_request
def before_request():
    session.permanent = True


def check_auth():
    blockchain_data = session.get("blockchain")
    logger.info(f"Checking auth. Session data: {blockchain_data}")
    if not blockchain_data or not blockchain_data.get("logged_in"):
        return False
    return True


def get_blockchain_instance(session_id):
    if session_id not in blockchain_instances:
        blockchain_data = session.get("blockchain")
        if not blockchain_data:
            return None
        blockchain_instances[session_id] = BlockChain(
            username=blockchain_data["username"],
            password=blockchain_data["password"],
            base_url="https://b1.ahmetshin.com/restapi/",
        )
    return blockchain_instances[session_id]


def save_hash(username, password, user_hash):
    try:
        filename = ACCOUNTS_FOLDER / f"{username}.json"
        with open(filename, "w") as f:
            json.dump(
                {"username": username, "password": password, "user_hash": user_hash},
                f,
                indent=4,
            )
        logger.info(f"Saved hash for user: {username}")
    except Exception as e:
        logger.error(f"Error saving hash for user {username}: {str(e)}")
        raise


def get_accounts():
    try:
        return [f.stem for f in ACCOUNTS_FOLDER.glob("*.json")]
    except Exception as e:
        logger.error(f"Error getting accounts: {str(e)}")
        return []


def load_account(username):
    try:
        filename = ACCOUNTS_FOLDER / f"{username}.json"
        if filename.exists():
            with open(filename) as f:
                return json.load(f)
        return None
    except Exception as e:
        logger.error(f"Error loading account {username}: {str(e)}")
        return None


def save_message(from_hash, to_hash, encrypted_message):
    try:
        dialog_participants = sorted([from_hash, to_hash])
        dialog_id = f"{dialog_participants[0]}_{dialog_participants[1]}"
        
        dialog_file = MESSAGES_FOLDER / f"dialog_{dialog_id}.json"
        is_encrypted = len(encrypted_message.get('encrypted_message').split(';')) == 5
        
        new_message = {
            'timestamp': datetime.datetime.now().isoformat(),
            'from_hash': from_hash,
            'to_hash': to_hash,
            'message': encrypted_message,
            'type': 'encrypted' if is_encrypted else 'plain'
        }
        
        if dialog_file.exists():
            with open(dialog_file, 'r', encoding='UTF-8') as f:
                dialog_data = json.load(f)
        else:
            dialog_data = {
                'participants': dialog_participants,
                'messages': []
            }
        
        # Проверяем, нет ли уже такого сообщения
        message_exists = any(
            msg['from_hash'] == from_hash and 
            msg['to_hash'] == to_hash and 
            msg['message'] == encrypted_message
            for msg in dialog_data['messages']
        )
        
        if not message_exists:
            dialog_data['messages'].append(new_message)
            dialog_data['last_update'] = new_message['timestamp']
            
            # Сохраняем обновленный диалог
            with open(dialog_file, 'w', encoding='UTF-8') as f:
                json.dump(dialog_data, f, indent=4)
            
        else:
            pass            
    except Exception as e:
        raise

def get_my_messages():
    try:
        blockchain_data = session.get('blockchain')
        if not blockchain_data:
            return []
            
        my_hash = blockchain_data['user_hash']
        all_messages = []
        
        for dialog_file in MESSAGES_FOLDER.glob('dialog_*.json'):
            try:
                with open(dialog_file, 'r', encoding='UTF-8') as f:
                    dialog_data = json.load(f)
                    

                if my_hash in dialog_data['participants']:
                    for msg in dialog_data['messages']:
                        all_messages.append({
                            'timestamp': msg['timestamp'],
                            'from_hash': msg['from_hash'],
                            'to_hash': msg['to_hash'],
                            'encrypted_message': msg['message'],
                            'type': msg['type']
                        })
                    
            except json.JSONDecodeError:
                logger.warning(f"Corrupted dialog file: {dialog_file}")
                continue
            except Exception as e:
                logger.error(f"Error reading dialog file {dialog_file}: {str(e)}")
                continue
        
        all_messages.sort(key=lambda x: x['timestamp'], reverse=True)
        return all_messages
        
    except Exception as e:
        logger.error(f"Error getting messages: {str(e)}")
        return []


def migrate_old_messages():
    try:
        old_messages_file = MESSAGES_FOLDER / "messages.json"
        if not old_messages_file.exists():
            return
            
        with open(old_messages_file, 'r', encoding='UTF-8') as f:
            old_messages = json.load(f)
            
        for msg in old_messages:
            save_message(
                from_hash=msg['from_hash'],
                to_hash=msg['to_hash'],
                encrypted_message=msg['encrypted_message']
            )
            
        old_messages_file.rename(old_messages_file.with_suffix('.json.bak'))
        logger.info("Successfully migrated old messages to new format")
        
    except Exception as e:
        logger.error(f"Error during message migration: {str(e)}")


def process_task(blockchain_instance, task):
    try:
        task_id = task['id']
        prev_hash = task.get('prev_hash', '')
        data = task.get('data_json')
        if data and all(key in data for key in ['message', 'from_hach', 'to_hach']):
            try:
                save_message(
                    from_hash=data['from_hach'],
                    to_hash=data['to_hach'],
                    encrypted_message=data['message']
                )
                logger.info(f"Сохранено сообщение от {data['from_hach'][:8]}")
            except Exception as e:
                pass
        result_hash = blockchain_instance.make_hash(prev_hash)
        solution_data = {
            'type_task': 'BlockTaskUser_Solution',
            'id': task_id,
            'hash': result_hash
        }
        
        send_result = blockchain_instance.send_task(solution_data)
        logger.info(
            f"Задача {task_id} обработана. Решение: {result_hash},\n"\
            f"CurrentTID:{threading.get_ident()},\n"\
            f"TIDS:{[[thread.name, thread.ident] for thread in threading.enumerate()]}"
        )
        
    except Exception as e:
        logger.error(f"Ошибка обработки задачи: {str(e)}")

def task_processing(blockchain_instance, session_id):
    logger.info(f"Запуск обработки задач для сессии: {session_id}")

    
    while session_id in task_threads and task_threads[session_id]['running']:
        try:
            result = blockchain_instance.get_chains()
            tasks_response = blockchain_instance.get_task().json()
            
            if tasks_response.get('tasks'):
                tasks = tasks_response['tasks']
                logger.info(f"Получено задач: {len(tasks)}")
                
                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = [
                        executor.submit(process_task, blockchain_instance, task)
                        for task in tasks
                    ]
                    for future in as_completed(futures):
                        future.result()
            else:
                logger.info('Нет задач')            
        except Exception as e:
            logger.error(f"Ошибка в цикле обработки задач: {str(e)}")
            
        time.sleep(20) 
    
    logger.info(f"Остановка обработки задач для сессии: {session_id}")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/accounts")
def get_account_list():
    try:
        accounts = get_accounts()
        return jsonify(accounts=accounts)
    except Exception as e:
        logger.error(f"Error getting account list: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/send-task', methods=['POST'])
def send_task():
    if not check_auth():
        logger.warning("Unauthorized attempt to send task")
        return jsonify({"error": "Not logged in"}), 401

    try:
        data = request.json
        session_id = request.cookies.get('session')
        blockchain = get_blockchain_instance(session_id)
        
        if not blockchain:
            return jsonify({"error": "Session expired"}), 401
        task_data = {
            'type_task': 'send_coins',
            'from_hach': data.get('from_hash'),
            'to_hach': data.get('to_hash'),
            'count_coins': int(data.get('coins', 0))
        }
        
        logger.info(f"Sending task with data: {task_data}")
        
        response = blockchain.send_task(task_data)
        result = response.json()
        
        logger.info(f"Send task raw response: {response.text}")
        logger.info(f"Send task parsed result: {result}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error sending task: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/account/<username>")
def get_account_data(username):
    try:
        account_data = load_account(username)
        if account_data:
            return jsonify(account_data)
        return jsonify({"error": "Account not found"}), 404
    except Exception as e:
        logger.error(f"Error getting account data for {username}: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            logger.warning("Login attempt without username or password")
            return jsonify({"error": "Username and password are required"}), 400

        blockchain = BlockChain(
            username=username,
            password=password,
            base_url="https://b1.ahmetshin.com/restapi/",
        )

        register_result = blockchain.register().json()
        logger.info(f"Register result: {register_result}")

        balance_result = blockchain.check_coins().json()
        logger.info(f"Balance result: {balance_result}")

        user_hash = blockchain.hach_user
        save_hash(username, password, user_hash)

        session.clear()
        session["blockchain"] = {
            "username": username,
            "password": password,
            "user_hash": user_hash,
            "logged_in": True,
        }
        session.modified = True

        session_id = request.cookies.get("session")
        blockchain_instances[session_id] = blockchain

        logger.info(f"Login successful. Session data: {session['blockchain']}")
        return jsonify(
            {
                "status": "success",
                "register_result": register_result,
                "balance_result": balance_result,
                "user_hash": user_hash,
            }
        )
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/check-balance", methods=["GET"])
def check_balance():
    if not check_auth():
        return jsonify({"error": "Not logged in"}), 401

    try:
        session_id = request.cookies.get("session")
        blockchain = get_blockchain_instance(session_id)

        if not blockchain:
            return jsonify({"error": "Session expired"}), 401

        result = blockchain.check_coins().json()
        return jsonify({"balance": result.get("coins", 0)})
    except Exception as e:
        logger.error(f"Error checking balance: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/encrypt-message", methods=["POST"])
def encrypt_message():
    if not check_auth():
        return jsonify({"error": "Не выполнен вход"}), 401

    try:
        data = request.json
        session_id = request.cookies.get("session")
        blockchain = get_blockchain_instance(session_id)

        if not blockchain:
            return jsonify({"error": "Сессия истекла"}), 401

        encryption_data = {
            "private_key": data.get("private_key"),
            "text": data.get("text"),
        }

        result = blockchain.encrypt(encryption_data).json()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Ошибка шифрования сообщения: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/decrypt-message", methods=["POST"])
def decrypt_message():
    if not check_auth():
        return jsonify({"error": "Not logged in"}), 401

    try:
        data = request.json
        session_id = request.cookies.get("session")
        blockchain = get_blockchain_instance(session_id)

        if not blockchain:
            return jsonify({"error": "Session expired"}), 401

        logger.info(f"Получены данные для расшифровки: {data}")
        
        # Отправляем данные в том виде, в котором они пришли
        result = blockchain.decrypt(data)
        decrypted_result = result.json()
        logger.info(f"Результат расшифровки: {decrypted_result}")

        if decrypted_result.get('success'):
            return jsonify({
                "message": decrypted_result.get('message', ''),
                "text": decrypted_result.get('text', '')
            })
        else:
            return jsonify({"error": "Decryption failed", "details": decrypted_result}), 400

    except Exception as e:
        logger.error(f"Error in decrypt_message: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/send-message", methods=["POST"])
def send_message():
    if not check_auth():
        return jsonify({"error": "Not logged in"}), 401

    try:
        data = request.json
        session_id = request.cookies.get("session")
        blockchain = get_blockchain_instance(session_id)

        if not blockchain:
            return jsonify({"error": "Session expired"}), 401

        task_data = {
            "type_task": "custom",
            "from_hach": data.get("from_hash"),
            "to_hach": data.get("to_hash"),
            "message": data.get("message"),
        }

        logger.info(f"Sending message with data: {task_data}")
        result = blockchain.send_task(task_data).json()
        logger.info(f"Message send result: {result}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error sending message: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/start-solving", methods=["POST"])
def start_solving():
    if not check_auth():
        return jsonify({"error": "Not logged in"}), 401

    try:
        session_id = request.cookies.get("session")
        blockchain = get_blockchain_instance(session_id)

        if not blockchain:
            return jsonify({"error": "Session expired"}), 401

        if session_id in task_threads and task_threads[session_id]["running"]:
            logger.info(f"Tasks already running for session: {session_id}")
            return jsonify({"message": "Tasks already running"})

        task_threads[session_id] = {
            "running": True,
            "thread": threading.Thread(
                target=task_processing, args=(blockchain, session_id)
            ),
        }
        task_threads[session_id]["thread"].daemon = True
        task_threads[session_id]["thread"].start()

        logger.info(f"Task solving started for session: {session_id}")
        return jsonify({"message": "Task solving started"})
    except Exception as e:
        logger.error(f"Error starting task solving: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/stop-solving", methods=["POST"])
def stop_solving():
    if not check_auth():
        return jsonify({"error": "Not logged in"}), 401

    try:
        session_id = request.cookies.get("session")
        if session_id in task_threads:
            task_threads[session_id]["running"] = False
            task_threads.pop(session_id)
            logger.info(f"Task solving stopped for session: {session_id}")
            return jsonify({"message": "Task solving stopped"})
        return jsonify({"message": "No tasks running"})
    except Exception as e:
        logger.error(f"Error stopping task solving: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/logout", methods=["POST"])
def logout():
    try:
        session_id = request.cookies.get("session")
        if session_id in blockchain_instances:
            del blockchain_instances[session_id]
        if session_id in task_threads:
            task_threads[session_id]["running"] = False
            task_threads.pop(session_id)
        session.clear()
        return jsonify({"message": "Logged out successfully"})
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/messages', methods=['GET'])
def get_messages():
    if not check_auth():
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        messages = get_my_messages()
        return jsonify({"messages": messages})
    except Exception as e:
        logger.error(f"Error getting messages: {str(e)}")
        return jsonify({"error": str(e)}), 500
    

@app.errorhandler(Exception)
def handle_error(e):
    logger.error(f"Unhandled error: {str(e)}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":

    ACCOUNTS_FOLDER.mkdir(exist_ok=True)
    MESSAGES_FOLDER.mkdir(exist_ok=True)

    try:
        migrate_old_messages()
    except Exception as e:
        logger.error(f"Error during message migration: {str(e)}")
        
    logger.info("Starting Blockchain Web Application")
    logger.info(f"Accounts folder: {ACCOUNTS_FOLDER}")
    logger.info(f"Messages folder: {MESSAGES_FOLDER}")

    app.run(debug=True, host="0.0.0.0", port=5001)
