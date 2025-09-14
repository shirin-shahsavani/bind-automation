from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    fernet_key: str
    client_ip: str
    KEY_AUTH_USER:str
    KEY_NAME:str
    KEY_SECRET:str


    key_algorithm: str = "hmac-sha256"
    locations_ip: dict = {
        "test": {"master": "10.60.110.227",
                 "slave": "10.60.110.228",
                 "forwarder_1": "10.60.110.229",
                 "forwarder_2": "10.60.110.229"
                 },

        "pardis": {"master": "192.168.55.151",
                   "slave": "10.60.115.60",
                   "forwarder_1": "192.168.55.154",
                   "forwarder_2": "172.16.110.210"
                   },

        "sandbox": {"master": "10.248.37.12",
                    "slave": "10.248.37.13",
                    "forwarder_1": "10.248.37.14",
                    "forwarder_2": "10.248.37.15"
                    },
        "khatam": {"master": "10.60.115.59",
                   "slave": "10.60.115.60",
                   "forwarder_1": "172.16.110.209",
                   "forwarder_2": "172.16.110.210"
                   },
        "bank": {"master": "10.60.115.59",
                 "slave": "10.60.115.60",
                 "forwarder_1": "172.16.110.209",
                 "forwarder_2": "172.16.110.210"
                 }
    }
    class Config:
        env_file = ".env"

key_algorithm = "hmac-sha256"

settings = Settings()
