import datetime
import hashlib
import pprint
from binascii import unhexlify, hexlify
import time
from pathlib import Path
import requests
import json


class BlockChain():
    data = {
    }
        
    def __init__(self, username, password, base_url):
        self.next=None
        self.hard = 5
        self.base_url = base_url
        self.hach_version = self.__hash_string(open(Path(__file__).resolve(), mode="r", encoding="utf-8").read()) 
        self.username = username
        self.password = password
        self.hach_user = self.__hash_string(json.dumps({'username':username, 'password':password}, ensure_ascii=False))
        self.data = {}
        
    def __hash_string(self,string):
        m256 = hashlib.sha256()
        m256.update(string.encode('utf-8'))
        return m256.hexdigest()
    
    def get_hash_object(self, obj_json):
        return hashlib.sha256(obj_json.encode('utf-8')).hexdigest()
    
    def get_version_file(self):
        result = {'user_hash': self.hach_user, 'hach_version_file':self.hach_version}
        print(result)
        return result
        
    def __to_hash256(self,string):
        return hexlify(hashlib.sha256(unhexlify(string)).digest()).decode("utf-8")
    
    def __request(self):
        url = self.base_url + self.method
        headers = {
        'Content-Type': 'application/json',
       
        }
        payload = {
            'version':self.hach_version,
            'user_hash': self.hach_user,
            'data':self.data,
            'username': self.username,
            'password': self.password
            }
        
        response = requests.post(url, 
                        timeout=10,
                        data=json.dumps(payload),
                        headers=headers, 
                        verify=False 
                        )
        response.close()
        return response
    # Регистрация пользователя
    def register(self):
        self.method = 'register'
        return self.__request()
    # проверить монеты
    def check_coins(self):
        self.method = 'check_coins'
        return self.__request()
    # получить задачу
    def get_task(self):
        self.method = 'get_task'
        return self.__request()
    # отправить задачу
    def send_task(self, data):
        self.data = data
        self.method = 'send_task'
        return self.__request()
     # Получить цепочки
    def get_chains(self):
        self.method = 'get_chains'
        return self.__request()
     #Засшифровать текст
    def encrypt(self,data):
        self.data = data
        self.method = 'encrypt'
        return self.__request()
     #Расшифровать текст
    def decrypt(self,data):
        self.data = data
        self.method = 'decrypt'
        return self.__request()
    # Создать hash
    def make_hash(self, prev_hash):
        s = 0
        start = time.time()
        hash = self.__to_hash256(prev_hash)
        while hash[:self.hard] != "0"*self.hard:
            hash = self.__to_hash256(hash)
            s = s + 1
        finist = time.time() - start
        return hash
        

