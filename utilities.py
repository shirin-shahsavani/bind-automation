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


b'gAAAAABn_2hzdFp6OL10LeiNj5AE_xgXmTMtIm3ec9oPnYywTH17I2X4qTl_gujLaqpUa6P3kg0FHHkFQRybYG16ip_jWlHF0g=='
b'gAAAAABn_2r3mWIGEltWlLxueSbImbMEINmy-FKw0OPH8GmHSnxWWoB00aSmfizUYSlmykoimO__ByjCenD3LTbFgP4D25HzRQ=='