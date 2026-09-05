from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    fernet_key: str
    client_ip: str
    KEY_AUTH_USER:str
    KEY_NAME:str
    KEY_SECRET:str
    KEY_ALGORITHM: str

    #master_Authentication
    KEY_NAME_MASTER: str
    KEY_SECRET_MASTER: str
    KEY_ALGORITHM_MASTER: str
    USER_AUTHENTICATION_KEY_MASTER:str
    MAX_RETRY:int

    # test
    TEST_MASTER: str
    TEST_SLAVE: str
    TEST_FORWARDERS: str

    AUTO_CREATE_PTR_FOR_A_RECORD: bool = True

    class Config:
        env_file = ".env"

    @property
    def locations_ip(self):
        return {
            "test": {
                "master": self.TEST_MASTER,
                "slave": self.TEST_SLAVE,
                "forwarders": [
                   ip.strip()
                   for ip in self.TEST_FORWARDERS.split(",")
                   if ip.strip()
                   ],
            },
        }


settings = Settings()




