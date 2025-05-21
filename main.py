import logging
from typing import Annotated, Union
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from fastapi import FastAPI , Header ,Request , HTTPException
from bind_manager import record_manager
import bind_manager.record_manager
import constants
import uvicorn
from utilities import authenticate_user
import bind_manager
#from fastapi import status


settings=constants.Settings()
app = FastAPI()

class RecordDetail(BaseModel):
    zone:str
    record_name:str
    record_value:str
    priority:int = 10
    ttl:int = 300
    location: str
    second_value : str = None


@app.post("/add/{record_type}/")
def add_record(record_type:str , detail:RecordDetail ,request:Request, token: Annotated[str | None, Header()] = None ):
    authenticate_user(request.client.host, token)
    print("location_ip_master")
    try:
        location_ip_master=settings.locations_ip[detail.location]["master"]
        location_ip_forwarder=settings.locations_ip[detail.location]["forwarder_1"]
    except:
        raise HTTPException(
            status_code=404,
            detail={"error": "This location doesn't exist" , "location": detail.location}
        )

    Add=record_manager.add_record(detail.zone,detail.record_name,record_type.upper(),detail.record_value, detail.ttl, detail.priority,location_ip_master,location_ip_forwarder)

    return{
        "message": "The record added"
    }


@app.post("/delete/{record_type}/")
def check_to_delete_record(record_type:str , detail:RecordDetail ,request:Request, token: Annotated[str | None, Header()] = None ):
    authenticate_user(request.client.host, token)
<<<<<<< Updated upstream
    location_ip_master=settings.locations_ip[detail.location]["master"]
    #location_ip_forwarder=settings.locations_ip[detail.location]["forwarder_1"]
    Delete=record_manager.del_record(detail.zone,detail.record_name,record_type, detail.record_value, location_ip_master)
=======
    try:
        location_ip_master=settings.locations_ip[detail.location]["master"]
        location_ip_forwarder=settings.locations_ip[detail.location]["forwarder_1"]
    except:
        raise HTTPException(
            status_code=404,
            detail={"error": "This location doesn't exist" , "location": detail.location}
        )

    Delete=record_manager.del_record(detail.zone,detail.record_name,record_type, detail.record_value, location_ip_master,location_ip_forwarder)
>>>>>>> Stashed changes
    return {
        "message": "The record deleted"
    }

@app.post("/update/{record_type}/")
def check_to_delete_record(record_type:str , detail:RecordDetail ,request:Request, token: Annotated[str | None, Header()] = None ):
    authenticate_user(request.client.host, token)
    location_ip_master=settings.locations_ip[detail.location]["master"]
    location_ip_forwarder=settings.locations_ip[detail.location]["forwarder_1"]
<<<<<<< Updated upstream
    update=record_manager.update_record_p(detail.zone,detail.record_name,record_type.upper(),detail.record_value,detail.second_value,detail.ttl,location_ip_master,location_ip_forwarder)
    return {
        "message": "The record value has changed successfully"
    }
=======
    bind_manager.record_manager.update_record_p(detail.zone,detail.record_name,record_type,detail.record_value,detail.second_value,detail.ttl,location_ip_master,location_ip_forwarder)
    raise HTTPException(
            status_code=200,
            detail={"messege":"The record value has changed successfully"} ###TODO check
        )

>>>>>>> Stashed changes


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)