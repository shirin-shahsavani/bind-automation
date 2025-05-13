from fastapi import HTTPException
import constants
import dns.query   #to use axfr 
import dns.zone    #Access zone's data
import dns.tsigkeyring   #authenticate
import dns.resolver   #chech zone
import dns.rdatatype
import requests
from cryptography.fernet import Fernet
from bind_manager import record_manager 
import main


check_forwarder_N = 1

def check_record_type(record_type):
    if record_type in ["A","AAAA", "NS" ,"MX","CNAME", "TXT", "PTR"]:
        return record_type in ["A","AAAA", "NS" ,"MX","CNAME", "TXT", "PTR"]
    else:
        raise HTTPException(
            status_code=405,
            detail={"error": "Invalid record type", "type": record_type}
        )  

def zone_existance(zone, location_ip_master):
    """Check if a zone exists on the nameserver."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [location_ip_master]
    try:
        resolver.resolve(zone, "SOA", lifetime=3)   
        return True
    except Exception as e: 
        raise HTTPException(
            status_code=404,
            detail={"error": "This zone does not exist or not availble.", "zone": zone} ###TODO check
        )  



def record_existance(zone,new_record,new_record_type,location_ip_master):
    """Retrieve zone data via AXFR transfer."""
    keyring = dns.tsigkeyring.from_text({constants.key_name: constants.key_secret})
    zone_data = dns.zone.from_xfr(dns.query.xfr(location_ip_master, zone, keyring=keyring, keyname=constants.key_name))
    records = []
    for name, node in zone_data.nodes.items():
        for rdataset in node.rdatasets:
            record_type = dns.rdatatype.to_text(rdataset.rdtype)
            records.append(f"{name}.{zone} {record_type}")

            if str(name)==new_record and record_type== new_record_type:
                return True
    return False


def record_existance_check_delete(zone,new_record,new_record_type,record_value, location_ip_master):
    """Retrieve zone data via AXFR transfer."""
    keyring = dns.tsigkeyring.from_text({constants.key_name: constants.key_secret})
    zone_data = dns.zone.from_xfr(dns.query.xfr(location_ip_master, zone, keyring=keyring, keyname=constants.key_name))
    records = []
    for name, node in zone_data.nodes.items():
        for rdataset in node.rdatasets:
            record_type = dns.rdatatype.to_text(rdataset.rdtype)
            records.append(f"{name}.{zone} {record_type}")
           
            

            if str(name)==new_record and record_type == new_record_type:
                check_the_value(zone,new_record, new_record_type, record_value ,location_ip_master)
                return True
                
        
                
                
    else:
        raise HTTPException(
            status_code=403,
            detail={"messege":"The record does not exist"} ###TODO check
    )


def check_forwarder_add(zone, new_record, new_record_type, new_record_value, location_ip_master, location_ip_forwarder):
    global check_forwarder_N
    if new_record_type in ["A", "AAAA"]:
        fqdn = f"{new_record}.{zone}"
        print("fqdn=", fqdn)
        query = dns.message.make_query(fqdn, dns.rdatatype.from_text(new_record_type))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        response = None
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_forwarder, timeout=3)
        except Exception as e:
            print(f"DNS query failed: {e} . forwarder does not available")
            response = None

        if response and response.answer:
            for answer in response.answer:
                for item in answer.items:
                    resolved_ips.append(str(item))
        if new_record_value in resolved_ips:
            print(f"Domain {fqdn} resolves to the expected IP: {new_record_value}")
            
            check_forwarder_N = 10
            raise HTTPException(
                status_code=200,
                detail={"message": "Added : Forwarder updated"} 
            )
        
        else:
            print(f"Domain {fqdn} exists, but IP does not match. Found: {resolved_ips}")
            return

    if new_record_type in ["PTR"]:
        PTR_record=f"{new_record}.{zone}"
        query = dns.message.make_query(PTR_record, dns.rdatatype.from_text(new_record_type))
        query.flags |= dns.flags.RD 
        response = None
        resolved_ips = []
        try:
           response = dns.query.udp(query, location_ip_forwarder, timeout=3)
        except Exception as e:
             print(f"DNS query failed: {e} . forwarder does not available")
             response = None

        if response and response.answer:
            for answer in response.answer:
                for item in answer.items:
                    resolved_ips.append(str(item))
        suffix =  f".{zone}."           ########## '.55.168.192.in-addr.arpa.'

        print (suffix)
        cleaned = [name.removesuffix(suffix) for name in resolved_ips]
        if new_record_value in cleaned:
            print(f"Domain {PTR_record} resolves to the expected IP: {new_record_value}")
            
            check_forwarder_N = 10
            raise HTTPException(
                status_code=200,
                detail={"message": "Forwarder updated"} 
            )
        else:
            print(f"Domain {PTR_record} exists, but IP does not match. Found: {cleaned}")
            
            return


 ###################################################################################

def check_forwarder_del(zone, new_record, new_record_type, new_record_value, location_ip_master, location_ip_forwarder):
    global check_forwarder_N
    if new_record_type in ["A", "AAAA"]:
        fqdn = f"{new_record}.{zone}"
        print("fqdn=", fqdn)
        query = dns.message.make_query(fqdn, dns.rdatatype.from_text(new_record_type))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        response = None
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_forwarder, timeout=3)
        except Exception as e:
            print(f"DNS query failed: {e} . forwarder does not available")
            response = None

        if response and response.answer:
            for answer in response.answer:
                for item in answer.items:
                    resolved_ips.append(str(item))
        if  resolved_ips == []:
            print(f"Domain {fqdn} resolves to the expected IP: {new_record_value}")
            
            check_forwarder_N = 10
            raise HTTPException(
                status_code=200,
                detail={"message": "Forwarder updated"} 
            )
        else:
            print(f"Domain {fqdn} exists, but IP does not match. Found: {resolved_ips}")
            
            reload_zone(zone, new_record, new_record_type, new_record_value,location_ip_master, location_ip_forwarder)
        main.delete_record_logic (zone,new_record,new_record_type, new_record_value ,location_ip_master)
        raise HTTPException(
                status_code=404,
                detail={"message": "Forwarder is not responding and the record deleted"} 
            )
    elif new_record_type == "MX":
        new_record_check = ' '.join(new_record_value.split()[1:]).rstrip('.')

    query = dns.message.make_query(zone, dns.rdatatype.MX, use_edns=False)
    response = dns.query.udp(query, location_ip_forwarder, timeout=3)

    resolved_values = []
    for answer in response.answer:
        for item in answer.items:
            resolved_values.append(str(item.exchange).lower().rstrip('.'))

    print("Searching for:", new_record_check)
    print("Resolved MX records:", resolved_values)

    if new_record_check.lower() in resolved_values:
        print(f"Domain {zone} has the expected MX record: {new_record_value}")
        check_forwarder_N = 10
        raise HTTPException(
            status_code=200,
            detail={"message": "Forwarder updated"} 
        )
    else:
        print(f"Domain {zone} exists, but MX record does not match. Found: {resolved_values}")
        reload_zone(zone, new_record, new_record_type, new_record_value,location_ip_master, location_ip_forwarder)
    main.delete_record_logic (zone,new_record,new_record_type, new_record_value ,location_ip_master)
    raise HTTPException(
            status_code=404,
            detail={"message": "Forwarder is not responding and the record deleted"} 

        )


def reload_zone(zone, new_record, new_record_type, new_record_value,location_ip_master, location_ip_forwarder):
    global check_forwarder_N
    command = "reload"
    api2_url = f"http://192.168.55.154:8000/{zone}/{command}/"

    key = b'g2MoSqxslTG5bZUb-ANegIbzRFq5PQnLxTubqD20nt4='
    cipher_suite = Fernet(key)
    client_ip = '192.168.55.1'
    token = cipher_suite.encrypt(client_ip.encode()).decode()

    headers = {"token": token}

    try:
        r = requests.get(api2_url, headers=headers, timeout=5)
        print("Reloaded")        
        check_forwarder_add(zone, new_record, new_record_type, new_record_value,location_ip_master, location_ip_forwarder)
    except requests.RequestException as e:
        print("Failed to call API:", e)    


def check_the_value(zone,record_name,record_type, record_value,location_ip_master):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [location_ip_master]

    try:
        if record_type in ["A" ,"AAAA" , "TXT"] :
            fqdn = f"{record_name}.{zone}".lower()
            answers = resolver.resolve(fqdn,record_type)
            resolved_ips = [str(answer) for answer in answers]
            resolved_ips=str(resolved_ips)
            if record_value in resolved_ips:
                print(f"Domain {fqdn} resolves to the expected IP: {record_value}")
                return True
            elif record_value not in resolved_ips:
                print(f"Domain {fqdn} exists, but IP does not match. Found: {resolved_ips}")
                raise HTTPException(
                    status_code=409,
                    detail={"error":"Ip does not match"}
            )

        
        elif record_type == "MX":
            answers = resolver.resolve(zone, "MX")
            resolved_values = [str(answer.exchange).lower().rstrip('.') for answer in answers]
            #print(f"Resolved MX records: {resolved_values}")
            print('search for: ', record_value)
            if record_value.lower() in resolved_values:
                print(f"Domain {zone} has the expected MX record: {record_value}")
                return True
            else:
                print(f"Domain {zone} exists, but MX record does not match. Found: {resolved_values}")
                raise HTTPException(
                    status_code=409,
                    detail={"error":"The value is not correct"}
            )


        else: 
            print ("Value didn't check")

    except:
        raise HTTPException(
            status_code=404,
            detail={"error": "value error"} ###TODO check
        ) 




