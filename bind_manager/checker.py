from fastapi import HTTPException
import constants
import dns.query   #to use axfr 
import dns.zone    #Access zone's data
import dns.tsigkeyring   #authenticate
import dns.resolver   #chech zone
import dns.rdatatype


def check_record_type(record_type):
    return record_type in ["A","AAAA", "NS" ,"MX","CNAME", "TXT", "PTR"]

def zone_existance(zone, location_ip_master):
    print("location_ip_master:",location_ip_master)
    """Check if a zone exists on the nameserver."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [location_ip_master]
    try:
        zone_existence = resolver.resolve(zone, "SOA", lifetime=3)   
        return True
    except Exception as e: 
        return False


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

def check_forwarder(zone,new_record,new_record_type, new_record_value,location_ip_forwarder):
    print (location_ip_forwarder)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [location_ip_forwarder]

    try:
        if new_record_type in ["A" ,"AAAA"] :
            fqdn = f"{new_record}.{zone}".lower()
            answers = resolver.resolve(fqdn,new_record_type)
            print(answers)
            resolved_ips = [str(answer) for answer in answers]
            print("Resolved IP addresses:", resolved_ips)
            if new_record_value in resolved_ips:
                print(f"Domain {fqdn} resolves to the expected IP: {new_record_value}")
            else:
                print(f"Domain {fqdn} exists, but IP does not match. Found: {resolved_ips}")
                raise HTTPException(
                    status_code=409,
                    detail={"error":"Ip does not match"}
            )

        
        elif new_record_type == "MX":
            new_record_check= ' '.join(new_record_value.split()[1:]).rstrip('.')
            answers = resolver.resolve(zone, "MX")
            resolved_values = [str(answer.exchange).lower().rstrip('.') for answer in answers]
            #print(f"Resolved MX records: {resolved_values}")
            print('search for: ', new_record_check)
            if new_record_check.lower() in resolved_values:
                print(f"Domain {zone} has the expected MX record: {new_record_value}")
            else:
                print(f"Domain {zone} exists, but MX record does not match. Found: {resolved_values}")

        else: 
            print ("Forwarder didn't check")

    except:
        raise HTTPException(
            status_code=404,
            detail={"error": "Forwarder Error"} ###TODO check
        )  
    
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
