from bind_manager import checker
from fastapi import HTTPException
import constants
import subprocess
import time
import dns.query   #to use axfr 
import dns.zone    #Access zone's data
import dns.update    #add record
import dns.tsigkeyring   #authenticate
import dns.resolver   #chech zone
import dns.rdatatype
import subprocess
import time
import dns.reversename
import requests
from cryptography.fernet import Fernet

def add_record(zone,new_record,new_record_type, new_record_value, ttl, priority, location_ip_master,location_ip_forwarder) :
    correct_type = checker.check_record_type(new_record_type)   ###Checking for correct type
    zone_exists=checker.zone_existance(zone,location_ip_master) ###Check if the zone exists on the nameserver
    if new_record_type == "PTR":
        print(new_record_type)
        return add_record_by_type(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder)
    else:
        record_exist=checker.record_existance(zone,new_record,new_record_type, location_ip_master)
        if record_exist:
            print(new_record_type)
            raise HTTPException(
                status_code=409,
                detail={"error": "This record exist"} ###TODO check
            )  
        
        return add_record_by_type(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)

def add_record_by_type(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder):
    match new_record_type:
        case "A":
            add_A_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
        case "PTR":
            add_PTR_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
        case "AAAA":
            add_AAAA_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
        case "MX":
            add_MX_A_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
        case "TXT":
            add_TXT_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
        case "NS":
            add_NS_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
        case "CNAME":
            add_CNAME_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
        #case _:
           # raise ValueError(f"Unsupported record type: {new_record_type}")
        
def trigger_reload(zone):
    api2_url = f"http://192.168.55.154:8000/{zone}/reload/"

    key = b'g2MoSqxslTG5bZUb-ANegIbzRFq5PQnLxTubqD20nt4='
    cipher_suite = Fernet(key)
    client_ip = '192.168.55.1'
    token = cipher_suite.encrypt(client_ip.encode()).decode()

    headers = {"token": token}
    try:
        r = requests.get(api2_url, headers=headers, timeout=5)
    except requests.RequestException as e:
        raise HTTPException(status_code=404, detail={"error": "Forwarder error after retries"})
    
def run_apply(zone):
    api1_url = f"http://192.168.55.151:8000/{zone}/apply/"

    key = b'g2MoSqxslTG5bZUb-ANegIbzRFq5PQnLxTubqD20nt4='
    cipher_suite = Fernet(key)
    client_ip = '192.168.55.1'
    token = cipher_suite.encrypt(client_ip.encode()).decode()

    headers = {"token": token}
    try:
        r = requests.get(api1_url, headers=headers, timeout=5)
    except requests.RequestException as e:
        raise HTTPException(status_code=404, detail={"error": "Forwarder error after retries"})

def update_func(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder):
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}), keyalgorithm=constants.key_algorithm) 
    update.add(new_record, ttl, new_record_type, new_record_value)
    response = dns.query.tcp(update, location_ip_master)
    run_apply(zone)
    if new_record_type in ["A" , "AAAA" , "PTR"]:
        check_forwarder_N=1
        while check_forwarder_N <= 10:
            checker.check_forwarder_add(zone,new_record,new_record_type, new_record_value,location_ip_master,location_ip_forwarder) 
            trigger_reload(zone)
            check_forwarder_N += 1
            print ("forwarder did not answer , reloading ...")
        delete_record_logic (zone,new_record,new_record_type, new_record_value ,location_ip_master,location_ip_forwarder)
        raise HTTPException(
                status_code=404,
                detail={"message": "Forwarder is not responding and the record deleted"}
        )

def del_record(zone,record_name,record_type, record_value, location_ip_master,location_ip_forwarder):
    correct_type = checker.check_record_type(record_type)
    if not correct_type:
        raise HTTPException(
            status_code=405,
            detail={"error": "Invalid record type", "type": record_type}
        )  
    zone_exists=checker.zone_existance(zone,location_ip_master)
    checker.record_existance_check_delete(zone ,record_name,record_type,record_value, location_ip_master)
    delete_record(zone,record_name,record_type,record_value,location_ip_master)
    check_forwarder_N=1
    while check_forwarder_N <= 10:
        checker.check_forwarder_del(zone, record_name, record_type, record_value, location_ip_master, location_ip_forwarder)   ###TODO apply the reload code when the forwarder does not answer
        check_forwarder_N += 1
        print(check_forwarder_N)
    


def delete_record_logic (zone,record_name,record_type,record_value ,location_ip_master, location_ip_forwarder) :
    correct_type = checker.check_record_type(record_type)
    zone_exists=checker.zone_existance(zone,location_ip_master)
    checker.record_existance_check_delete(zone ,record_name,record_type,record_value, location_ip_master)
    delete_record(zone,record_name,record_type,record_value,location_ip_master)

def update_record_p(zone,record_name,record_type,record_value,second_value,ttl, location_ip_master,location_ip_forwarder):
    correct_type =checker.check_record_type(record_type)
    if not correct_type:
        raise HTTPException(
            status_code=405,
            detail={"error": "Invalid record type", "type": record_type}
        )  
    checker.zone_existance(zone, location_ip_master)
    checker.record_existance_check_delete(zone ,record_name,record_type,record_value, location_ip_master)
    update_record(zone,record_name,record_type,second_value,ttl,location_ip_master,location_ip_forwarder )
    check_forwarder_N=1
    while check_forwarder_N <= 10:
        checker.check_forwarder_add(zone,record_name,record_type, second_value ,location_ip_master,location_ip_forwarder)   ###TODO apply the reload code when the forwarder does not answer
        check_forwarder_N += 1
        print(check_forwarder_N)





def add_A_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder):
    update_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder)
    #ptr_zone = ".".join(new_record_value.split(".")[:3][::-1]) + ".in-addr.arpa"
    #ptr_name = new_record_value.split(".")[-1]
    #ptr_value=f"{new_record}.{zone}."
    #update_func(ptr_zone,ptr_name,"PTR", ptr_value, ttl, location_ip_master,location_ip_forwarder)
    #TODO: return status

def add_PTR_record(zone,new_record,new_record_type, new_record_value,ttl, location_ip_master, location_ip_forwarder):
    def get_all_ptr_records(zone_name, location_ip_master):
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(
                    where=location_ip_master,
                    zone=zone_name,
                    keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}),
                    keyname=dns.name.from_text(constants.key_name),
                    keyalgorithm=constants.key_algorithm
                )
            )

            ptr_records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    if rdataset.rdtype == dns.rdatatype.PTR:
                        for rdata in rdataset:
                            full_name = f"{name}.{zone.origin}"
                            #print(f"{full_name} → {rdata.target}")
                            ptr_records.append((full_name, str(rdata.target)))

            return ptr_records

        except Exception as e:
            print(f"Zone transfer failed: {e}")
            return []

    ptr_records=get_all_ptr_records(zone, location_ip_master)
    targets_only = [record[1] for record in ptr_records]
    if new_record_value in targets_only:
        raise HTTPException(
                status_code=409,
                detail={"error":"The value of the PTR record exists"}
        )
    else:
        print((zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder))
        update_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder)
        raise HTTPException(
            status_code=200,
            detail={"message": "record added successfully"} 
        )

def add_AAAA_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder):
    update_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
    
def add_MX_A_record(zone,new_record, new_record_type,new_record_value, ttl,location_ip_master, location_ip_forwarder , mx_priority=10):
    new_record_type= "A"
    add_A_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
    new_record_type= "MX"
    new_record_value=f"{mx_priority} {new_record}.{zone}."
    #new_record_value_check=f"{new_record}.{zone}."
    update_func(zone,"@",new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
    update_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder)
    raise HTTPException(
        status_code=200,
        detail={"message": "record added successfully"} ###TODO check
    )  

def add_TXT_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder):
    update_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
    raise HTTPException(
            status_code=200,
            detail={"message": "record added successfully"} 
        )

  
def add_NS_record(zone, new_record, new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder):
    new_ns_record = f"{new_record}.{zone}."
    keyring = dns.tsigkeyring.from_text({constants.key_name: constants.key_secret})

    
    try:
        zone_data = dns.zone.from_xfr(dns.query.xfr(location_ip_master, zone, keyring=keyring, keyname=dns.name.from_text(constants.key_name),keyalgorithm=constants.key_algorithm))
    except Exception as e:
        print(f"AXFR failed: {e}")
        return
    
    record_found = False
    for name, node in zone_data.nodes.items():
        for rdataset in node.rdatasets:
            record_type = dns.rdatatype.to_text(rdataset.rdtype)
            if str(f"{name}.{zone}.") == new_ns_record:
                print("NS record already exists")
                record_found = True
                break
        if record_found:
            break

    if not record_found:

        print(f"Adding A record for {new_record}.{zone} → {new_record_value}")
        update_func(zone, f"{new_record}", "A", new_record_value, ttl, location_ip_master, location_ip_forwarder)

        print(f"Adding NS record for {zone} → {new_ns_record}")
        update_func(zone, "@", "NS", f"{new_record}", ttl, location_ip_master, location_ip_forwarder)
        
        raise HTTPException(
            status_code=200,
            detail={"message": "NS & A record added successfully"} ###TODO check
    )  
 
def add_CNAME_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder):
    update_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder)
    raise HTTPException(
        status_code=200,
        detail={"message": "CNAME record added successfully"} 
    )



def delete_record(zone,new_record,new_record_type,record_value,location_ip_master):
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}), keyalgorithm=constants.key_algorithm) 
    update.delete(new_record, new_record_type)
    response = dns.query.tcp(update, location_ip_master)
    print(response)
    run_apply(zone)



def update_record(zone,record_name,record_type,  new_record_value,ttl, location_ip_master, location_ip_forwarder):
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}), keyalgorithm=constants.key_algorithm) 
    update.replace(record_name, ttl, record_type, new_record_value)
    response = dns.query.tcp(update, location_ip_master)
    print(response)
    run_apply(zone)