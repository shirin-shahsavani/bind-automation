import logging
from typing import Annotated, Union
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from fastapi import FastAPI , Header ,Request , HTTPException
from bind_manager import record_manager
import bind_manager.checker
import bind_manager.record_manager
import constants
import uvicorn 
from utilities import authenticate_user
import bind_manager


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
    location_ip_master=settings.locations_ip[detail.location]["master"]
    location_ip_forwarder=settings.locations_ip[detail.location]["forwarder_1"]
    A=record_manager.add_record(
        detail.zone,
        detail.record_name,
        record_type.upper(),
        detail.record_value, 
        detail.ttl, 
        detail.priority,
        location_ip_master,
        location_ip_forwarder
        )
    
<<<<<<< Updated upstream
    return
=======
    # return{
    #     "message": "The record added"
    # } 
>>>>>>> Stashed changes


@app.post("/delete/{record_type}/")
def check_to_delete_record(record_type:str , detail:RecordDetail ,request:Request, token: Annotated[str | None, Header()] = None ):
    authenticate_user(request.client.host, token)
    location_ip_master=settings.locations_ip[detail.location]["master"]
    location_ip_forwarder=settings.locations_ip[detail.location]["forwarder_1"]
<<<<<<< Updated upstream
    bind_manager.checker.check_record_type(record_type)
    bind_manager.checker.zone_existance(detail.zone, location_ip_master)
    bind_manager.checker.record_existance_check_delete(detail.zone ,detail.record_name,record_type.upper(),detail.record_value, location_ip_master)
    bind_manager.record_manager.delete_record(detail.zone,detail.record_name,record_type.upper(),detail.record_value,location_ip_master)
    raise HTTPException(
            status_code=200,
            detail={"messege":"The record deleted successfully"} ###TODO check
        )  
=======
    Delete=record_manager.del_record(detail.zone,detail.record_name,record_type, detail.record_value, location_ip_master,location_ip_forwarder)
    return {
        "message": "The record deleted"
    } 
>>>>>>> Stashed changes

def delete_record_logic (zone,record_name,record_type,record_value ,location_ip_master, location_ip_forwarder) :
    result = record_manager.del_record(
        zone, record_name, record_type, record_value, location_ip_master ,location_ip_forwarder
    )
    return result



@app.post("/update/{record_type}/")
def check_to_delete_record(record_type:str , detail:RecordDetail ,request:Request, token: Annotated[str | None, Header()] = None ):
    authenticate_user(request.client.host, token)
    location_ip_master=settings.locations_ip[detail.location]["master"]
    location_ip_forwarder=settings.locations_ip[detail.location]["forwarder_1"]
    bind_manager.checker.check_record_type(record_type)
    bind_manager.checker.zone_existance(detail.zone, location_ip_master)
    bind_manager.checker.record_existance_check_delete(detail.zone ,detail.record_name,record_type.upper(),detail.record_value, location_ip_master)
    bind_manager.record_manager.update_record(detail.zone,detail.record_name,record_type.upper(),detail.second_value,detail.ttl,location_ip_master,location_ip_forwarder )
    raise HTTPException(
            status_code=200,
            detail={"messege":"The record value has changed successfully"} ###TODO check
        )  



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)