from bind_manager import checker
from fastapi import HTTPException
from cryptography.fernet import Fernet





key = b'gEBfVhumi1UeTfMpitUEwsQy5ix_Ot_9OIZBGU6p360='
cipher_suite = Fernet(key)
client_ip = '10.61.128.30'
token = cipher_suite.encrypt(client_ip.encode()).decode()
print(token)
