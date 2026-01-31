##################Libararies####################
import asyncio
import logging
from typing import Annotated
from pydantic import BaseModel , field_validator
from fastapi import FastAPI , Header ,Request , HTTPException
from bind_manager import record_manager
import uvicorn
from config.settings import settings
from utilities import authenticate_user , authenticate_user_master
from fastapi.responses import JSONResponse
from config.logging_config import setup_logging
import uuid
from bind_manager import checker
from run import run_command
from typing import Annotated, Union



setup_logging()
logger = logging.getLogger(__name__)
app = FastAPI()
# Disable watchfiles logging to prevent unnecessary log noise
logging.getLogger("watchfiles").propagate = False
logging.getLogger("watchfiles").disabled = True

lock = asyncio.Lock()


class RecordDetail(BaseModel):
    zone:str
    record_name:str
    record_value:str
    priority:int = 10
    ttl:int = 300
    location:str
    second_value : str = None

class CommandDetail(BaseModel):
    zone: str
    command: str

@field_validator("location")
def validate_location( cls , location: str):
    if location not in settings.locations_ip:
        logger.warning(f"Invalid location provided: {location}")
        raise HTTPException(
            status_code=404, #NOT_FOUND
            detail={ "error": "This location does not exist", "location": location}
        )
    return location

@app.post("/add/{record_type}/")
async def add_record(record_type:str , detail:RecordDetail ,request:Request, token: Annotated[str | None, Header()] = None ):
    if lock.locked():
        raise HTTPException(status_code=429, detail="The server is busy. Please try again later.")
    async with lock:
        logger.info(f"Add request from {request.client.host} for zone={detail.zone}, record={detail.record_name}, type={record_type}")
        authenticate_user(request.client.host, token)
        location_ip_master, location_ip_forwarder_1, location_ip_forwarder_2 = get_location_ips(detail.location)
        operation_id = str(uuid.uuid4())
        record_manager.add_record(detail.zone,detail.record_name,record_type.upper(),detail.record_value, detail.ttl, detail.priority,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2,operation_id=operation_id)
        logger.info(f"Record added successfully: {detail.record_name}.{detail.zone} -> {detail.record_value}")
        return JSONResponse(content={
            "message": "Record created successfully."
            })

@app.post("/delete/{record_type}/")
async def delete_record(record_type:str , detail:RecordDetail ,request:Request, token: Annotated[str | None, Header()] = None ):
    if lock.locked():
        raise HTTPException(status_code=429, detail="The server is busy. Please try again later.")
    async with lock:
        logger.info(f"Delete request from {request.client.host} for zone={detail.zone}, record={detail.record_name}, type={record_type}")
        authenticate_user(request.client.host, token)
        location_ip_master, location_ip_forwarder_1, location_ip_forwarder_2 = get_location_ips(detail.location)
        operation_id = str(uuid.uuid4())
        record_manager.del_record(detail.zone,detail.record_name,record_type, detail.record_value, detail.ttl, detail.priority, location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2,operation_id=operation_id)
        logger.info(f"Record deleted successfully: {detail.record_name}.{detail.zone} -> {detail.record_value}")
        return JSONResponse(content={
            "message": "The record was successfully deleted."
        })
    

@app.post("/update/{record_type}/")
async def update_record(record_type:str , detail:RecordDetail ,request:Request, token: Annotated[str | None, Header()] = None ):
    if lock.locked():
        raise HTTPException(status_code=429, detail="The server is busy. Please try again later.")
    async with lock:
        logger.info(f"Update request from {request.client.host} for zone={detail.zone}, record={detail.record_name}, type={record_type}")
        authenticate_user(request.client.host, token)
        location_ip_master, location_ip_forwarder_1, location_ip_forwarder_2 = get_location_ips(detail.location)
        record_manager.update_record_progress(detail.zone,detail.record_name,record_type,detail.record_value,detail.second_value,detail.ttl,detail.priority,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2)
        logger.info(f"Record updated successfully: {detail.record_name}.{detail.zone} -> {detail.second_value}")
        return JSONResponse(content={
            "message": "The record value was successfully updated."
        })

def get_location_ips(location: str):
    loc_data = settings.locations_ip.get(location)
    if not loc_data:
        logger.error(f"Invalid location in get_location_ips: {location}")
        raise HTTPException(
            status_code=403,
            detail={"error": "Invalid location provided", "location": location}
        )
    return loc_data["master"], loc_data["forwarder_1"], loc_data["forwarder_2"]


@app.post("/{zone}/{command}/")
def run_command_func(zone:str , command:str,  detail:RecordDetail, request:Request, token: Annotated[str | None, Header()] = None ):
    location_ip_master = get_location_ips(detail.location)
    authenticate_user_master(request.client.host, token)
    checker.check_command_type(command)
    checker.zone_existance(zone,location_ip_master)
    run_command(zone)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
