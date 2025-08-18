from cryptography.fernet import Fernet
from fastapi import HTTPException

def authenticate_user(real_ip, token):
    key='gEBfVhumi1UeTfMpitUEwsQy5ix_Ot_9OIZBGU6p360='
    cipher_suite=Fernet(key)
    token_ip = cipher_suite.decrypt(token)
    print(token_ip)
    if token_ip.decode("utf-8") != real_ip:
        raise HTTPException(
            status_code=403,
            detail={"messege":"Invalid token"} ###TODO check
        )  

from cryptography.fernet import Fernet

def generate_token(ip: str) -> str:
    key = 'gEBfVhumi1UeTfMpitUEwsQy5ix_Ot_9OIZBGU6p360='  # same key as in authenticate_user
    cipher_suite = Fernet(key)
    token = cipher_suite.encrypt(ip.encode())
    return token.decode()  # return as string for HTTP


print(generate_token("127.0.0.1"))
# Output: gAAAAABm... (long token string)
















b'gAAAAABn_2hzdFp6OL10LeiNj5AE_xgXmTMtIm3ec9oPnYywTH17I2X4qTl_gujLaqpUa6P3kg0FHHkFQRybYG16ip_jWlHF0g=='
b'gAAAAABodfFSZeBmeMGDwWER27o2Ogl3uVD7SHD1n-1H95rup9n_5UMFjogefRA-a-IaOQLqmpX_xiTDurey_6qBDu5LqsefBQ=='
b'gAAAAABn_2r3mWIGEltWlLxueSbImbMEINmy-FKw0OPH8GmHSnxWWoB00aSmfizUYSlmykoimO__ByjCenD3LTbFgP4D25HzRQ=='