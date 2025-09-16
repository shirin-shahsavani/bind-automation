from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    fernet_key: str
    client_ip: str
    KEY_AUTH_USER:str
    KEY_NAME:str
    KEY_SECRET:str
    key_algorithm: str = "hmac-sha256"

    # test
    TEST_MASTER: str
    TEST_SLAVE: str
    TEST_FORWARDER_1: str
    TEST_FORWARDER_2: str

    # pardis
    PARDIS_MASTER: str
    PARDIS_SLAVE: str
    PARDIS_FORWARDER_1: str
    PARDIS_FORWARDER_2: str

    # sandbox
    SANDBOX_MASTER: str
    SANDBOX_SLAVE: str
    SANDBOX_FORWARDER_1: str
    SANDBOX_FORWARDER_2: str

    # khatam
    KHATAM_MASTER: str
    KHATAM_SLAVE: str
    KHATAM_FORWARDER_1: str
    KHATAM_FORWARDER_2: str

    # bank
    BANK_MASTER: str
    BANK_SLAVE: str
    BANK_FORWARDER_1: str
    BANK_FORWARDER_2: str

    class Config:
        env_file = ".env"

    @property
    def locations_ip(self):
        return {
            "test": {
                "master": self.TEST_MASTER,
                "slave": self.TEST_SLAVE,
                "forwarder_1": self.TEST_FORWARDER_1,
                "forwarder_2": self.TEST_FORWARDER_2,
            },
            "pardis": {
                "master": self.PARDIS_MASTER,
                "slave": self.PARDIS_SLAVE,
                "forwarder_1": self.PARDIS_FORWARDER_1,
                "forwarder_2": self.PARDIS_FORWARDER_2,
            },
            "sandbox": {
                "master": self.SANDBOX_MASTER,
                "slave": self.SANDBOX_SLAVE,
                "forwarder_1": self.SANDBOX_FORWARDER_1,
                "forwarder_2": self.SANDBOX_FORWARDER_2,
            },
            "khatam": {
                "master": self.KHATAM_MASTER,
                "slave": self.KHATAM_SLAVE,
                "forwarder_1": self.KHATAM_FORWARDER_1,
                "forwarder_2": self.KHATAM_FORWARDER_2,
            },
            "bank": {
                "master": self.BANK_MASTER,
                "slave": self.BANK_SLAVE,
                "forwarder_1": self.BANK_FORWARDER_1,
                "forwarder_2": self.BANK_FORWARDER_2,
            },
        }


settings = Settings()
