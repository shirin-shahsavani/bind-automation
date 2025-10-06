from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException
from config.settings import settings

def authenticate_user(real_ip, token):
    key = settings.KEY_AUTH_USER
    cipher_suite = Fernet(key)
    try:
        token_ip = cipher_suite.decrypt(token)
    except InvalidToken:
        raise HTTPException(
            status_code=403,
            detail={"message": "Token decryption failed or token is invalid"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": f"Unexpected error during token validation: {str(e)}"}
        )

    if token_ip.decode("utf-8") != real_ip:
        raise HTTPException(
            status_code=403,
            detail={"message": "Invalid token"}
        )

def generate_token(ip: str) -> str:
    key = settings.KEY_AUTH_USER  # same key as in authenticate_user
    cipher_suite = Fernet(key)
    token = cipher_suite.encrypt(ip.encode())
    return token.decode()  # return as string for HTTP

















