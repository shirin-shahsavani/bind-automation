from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    fernet_key: str
    client_ip: str

    class Config:
        env_file = ".env"

settings = Settings()
