from bind_manager import checker
from fastapi import HTTPException
from cryptography.fernet import Fernet





key = b'K5EJ71J77QbPjgu3/C23m1A0jM4YrDxl659dEg8Ros4='
cipher_suite = Fernet(key)
client_ip = '127.0.0.1'
token = cipher_suite.encrypt(client_ip.encode()).decode()
print(token)
