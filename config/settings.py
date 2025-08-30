from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    fernet_key: str
    client_ip: str
    KEY_AUTH_USER:str
    KEY_NAME:str
    KEY_SECRET:str

    class Config:
        env_file = ".env"

settings = Settings()
