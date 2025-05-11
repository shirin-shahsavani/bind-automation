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

def add_record(zone,new_record,new_record_type, new_record_value, ttl, priority, location_ip_master,location_ip_forwarder) :
    correct_type = checker.check_record_type(new_record_type)   ###Checking for correct type
    zone_exists=checker.zone_existance(zone,location_ip_master) ###Check if a zone exists on the nameserver
    if new_record_type == "PTR":
        return add_record_by_type(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder)
    record_exist=checker.record_existance(zone,new_record,new_record_type, location_ip_master)
    if record_exist:
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
        

def update_func(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder):
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}), keyalgorithm=constants.key_algorithm) 
    update.add(new_record, ttl, new_record_type, new_record_value)
    response = dns.query.tcp(update, location_ip_master)
    print(response)
       #TODO: call freeze and thaw API
    
    #checker.check_forwarder(zone,new_record,new_record_type, new_record_value,location_ip_forwarder)

def add_A_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder):
    update_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder)
    ptr_zone = ".".join(new_record_value.split(".")[:3][::-1]) + ".in-addr.arpa"
    ptr_name = new_record_value.split(".")[-1]
    ptr_value=f"{new_record}.{zone}."
    update_func(ptr_zone,ptr_name,"PTR", ptr_value, ttl, location_ip_master,location_ip_forwarder)
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
        print("The value of record exists for this PTR record")
        raise HTTPException(
                status_code=409,
                detail={"error":"The value of the PTR record exists"}
        )
    else:
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


def run_command(zone):
    remote_user = "shirin"
    password = "123456"  # Your password for sudo
    
    # Command to freeze and thaw the zone
    command_1 = f"echo {password} | sudo -S /usr/sbin/rndc freeze {zone}"
    command_2 = f"echo {password} | sudo -S /usr/sbin/rndc thaw {zone}"

    # Execute the freeze command
    ssh_command = ["ssh", f"{remote_user}@{constants.nameserver}", command_1]
    result = subprocess.run(ssh_command, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"Freeze command executed successfully for {zone}!")
    else:
        print(f"Error executing freeze command for {zone}: {result.stderr}")
        return  # Exit if freeze command fails

    # Add a short delay before running the thaw command
    time.sleep(5)  # Sleep for 2 seconds or adjust based on your needs

    # Execute the thaw command
    ssh_command = ["ssh", f"{remote_user}@{constants.nameserver}", command_2]
    result = subprocess.run(ssh_command, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"Thaw command executed successfully for {zone}!")
        
    else:
        print(f"Error executing thaw command for {zone}: {result.stderr}")



def delete_record(zone,new_record,new_record_type,record_value,location_ip_master):
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}), keyalgorithm=constants.key_algorithm) 
    update.delete(new_record, new_record_type)
    response = dns.query.tcp(update, location_ip_master)
    print(response)



def update_record(zone,record_name,record_type,  new_record_value,ttl, location_ip_master, location_ip_forwarder):
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}), keyalgorithm=constants.key_algorithm) 
    update.replace(record_name, ttl, record_type, new_record_value)
    response = dns.query.tcp(update, location_ip_master)
    print(response)
