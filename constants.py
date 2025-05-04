from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    
    key_name:str = "mykey"
    key_secret:str = "K5EJ71J77QbPjgu3/C23m1A0jM4YrDxl659dEg8Ros4=" 
    key_algorithm:str = "hmac-sha256"
    locations_ip: dict = {
    "pardis" : {"master" : "192.168.55.151",
                "slave" : "10.60.115.60",
                "forwarder_1": "192.168.55.154",
                "forwarder_2": "172.16.110.210"
                },

    "sandbox" : {"master" : "10.248.37.12",
                "slave" : "10.248.37.13",
                "forwarder_1": "10.248.37.14",
                "forwarder_2": "10.248.37.15"
                },
    "khatam" : {"master" : "10.60.115.59",
                "slave" : "10.60.115.60",
                "forwarder_1": "172.16.110.209",
                "forwarder_2": "172.16.110.210"
                },
    "bank" : {"master" : "10.60.115.59",
                "slave" : "10.60.115.60",
                "forwarder_1": "172.16.110.209",
                "forwarder_2": "172.16.110.210"
                }

}

key_name = "mykey"
key_secret = "K5EJ71J77QbPjgu3/C23m1A0jM4YrDxl659dEg8Ros4=" 
key_algorithm = "hmac-sha256"