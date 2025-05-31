from fastapi import HTTPException
import constants
import dns.query   #to use axfr
import dns.zone    #Access zone's data
import dns.tsigkeyring   #authenticate
import dns.resolver   #chech zone
import dns.rdatatype
import requests
from cryptography.fernet import Fernet
import main
import ipaddress



check_forwarder_N = 1

def check_record_type(record_type):
    if record_type in ["A","AAAA", "NS" ,"MX","CNAME", "TXT", "PTR"]:
        return True

    raise HTTPException(
        status_code=405,
        detail={"error": "Invalid record type", "type": record_type}
    )

def zone_existance(zone, location_ip_master):
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
    if new_record_type in ["A" , "AAAA"]:
        fqdn = f"{new_record}.{zone}"
        query = dns.message.make_query(fqdn, dns.rdatatype.from_text(new_record_type))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_forwarder, timeout=3)
        except Exception as e:
            print(f"DNS query failed: {e} . forwarder does not available")
            response = None

        if response and response.answer:
            resolved_ips = [str(item) for answer in response.answer for item in answer.items]
        if new_record_type == "A":
            if new_record_value in resolved_ips:
                print(f"Domain {fqdn} resolves to the expected IP: {new_record_value}")
                check_forwarder_N = 10
                return check_forwarder_N
            else:
                print(f"Domain {fqdn} exists, but IP does not match. Found: {resolved_ips}")
        if new_record_type == "AAAA":
            try:
                expected_ip = ipaddress.IPv6Address(new_record_value)
                normalized_resolved = [ipaddress.IPv6Address(ip) for ip in resolved_ips]

                if expected_ip in normalized_resolved:
                    print(f"Domain {fqdn} resolves to the expected IP: {new_record_value}")
                    check_forwarder_N = 10
                    return check_forwarder_N
                else:
                    print(f"Domain {fqdn} exists, but IP does not match. Found: {resolved_ips}")

            except Exception as e:
                print(f"Invalid IPv6 address provided: {e}")



    if new_record_type in ["PTR"]:
        PTR_record=f"{new_record}.{zone}"
        query = dns.message.make_query(PTR_record, dns.rdatatype.from_text(new_record_type))
        query.flags |= dns.flags.RD
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
        suffix =  f".{zone}."

        print (suffix)
        cleaned = [name.removesuffix(suffix) for name in resolved_ips]
        if new_record_value in cleaned:
            print(f"Domain {PTR_record} resolves to the expected IP: {new_record_value}")

            check_forwarder_N = 10
            # raise HTTPException(
            #     status_code=200,
            #     detail={"message": "Record added and the forwarder Checked"}
            # )
            return check_forwarder_N

        else:
            print(f"Domain {PTR_record} exists, but IP does not match. Found: {cleaned}")
    # if new_record_type in ["MX"] :
    #     print("###########################")
    #     new_record_check= ' '.join(new_record_value.split()[1:]).rstrip('.')
    #     print ("new_record_check:",new_record_check)
    #     resolver = dns.resolver.Resolver()
    #     resolver.nameservers = [location_ip_forwarder]
    #     answers = resolver.resolve(zone, "MX")
    #     resolved_values = [str(answer.exchange).lower().rstrip('.') for answer in answers]
    #     print(resolved_values)
    #     print('search for: ', new_record_check)
    #     if new_record_check.lower() in resolved_values:
    #         print(f"Domain MX resolves to the expected IP: {new_record_check}")
    #         check_forwarder_N = 10
    #
    #     else:
    #         print(f"Domain MX exists, but IP does not match. Found: {resolved_values}")

    return None


 ###################################################################################

def check_forwarder_del(zone, new_record, new_record_type, new_record_value, location_ip_master, location_ip_forwarder):
    if new_record_type in ["A", "AAAA"]:
        fqdn = f"{new_record}.{zone}"
        print("fqdn=", fqdn)
        query = dns.message.make_query(fqdn, dns.rdatatype.from_text(new_record_type))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_forwarder, timeout=3)
        except Exception as e:
            print(f"DNS query failed: {e} . forwarder does not available")
            response = None

        resolved_ips = [str(item) for answer in response.answer for item in answer.items]
###########################################################################
        if new_record_type == "A":
            if new_record_value not in resolved_ips:
                print(f"Record {fqdn} deleted: {new_record_value}")
                check_forwarder_N = 10
                return check_forwarder_N
            else:
                print(f"Record {fqdn} is still exist. Found: {resolved_ips}")
        if new_record_type == "AAAA":
            try:
                expected_ip = ipaddress.IPv6Address(new_record_value)
                normalized_resolved = [ipaddress.IPv6Address(ip) for ip in resolved_ips]

                if expected_ip in normalized_resolved:
                    print(f"Domain {fqdn} resolves to the expected IP: {new_record_value}")
                    check_forwarder_N = 10
                    return check_forwarder_N
                else:
                    print(f"Domain {fqdn} exists, but IP does not match. Found: {resolved_ips}")

            except Exception as e:
                print(f"Invalid IPv6 address provided: {e}")
    return




    #     if not resolved_ips:
    #         print(f"Domain {fqdn} resolves to the expected IP: {new_record_value}")
    #
    #         check_forwarder_N = 10
    #         raise HTTPException(
    #             status_code=200,
    #             detail={"message": "Forwarder updated"}
    #         )
    #     else:
    #         print(f"Domain {fqdn} exists, but IP does not match. Found: {resolved_ips}")
    #
    #     trigger_reload(zone, new_record, new_record_type, new_record_value,location_ip_master, location_ip_forwarder)
    #     main.delete_record_logic (zone,new_record,new_record_type, new_record_value ,location_ip_master)
    #     raise HTTPException(
    #             status_code=404,
    #             detail={"message": "Forwarder is not responding and the record deleted"}
    #         )
    # elif new_record_type == "MX":
    #     new_record_check = ' '.join(new_record_value.split()[1:]).rstrip('.')
    #
    # query = dns.message.make_query(zone, dns.rdatatype.MX, use_edns=False)
    # response = dns.query.udp(query, location_ip_forwarder, timeout=3)
    #
    # resolved_values = []
    # for answer in response.answer:
    #     for item in answer.items:
    #         resolved_values.append(str(item.exchange).lower().rstrip('.'))
    #
    # print("Searching for:", new_record_check)
    # print("Resolved MX records:", resolved_values)
    #
    # if new_record_check.lower() in resolved_values:
    #     print(f"Domain {zone} has the expected MX record: {new_record_value}")
    #     check_forwarder_N = 10
    #     raise HTTPException(
    #         status_code=200,
    #         detail={"message": "Forwarder updated"}
    #     )
    # else:
    #     print(f"Domain {zone} exists, but MX record does not match. Found: {resolved_values}")
    #     reload_zone(zone, new_record, new_record_type, new_record_value,location_ip_master, location_ip_forwarder)
    # main.delete_record_logic (zone,new_record,new_record_type, new_record_value ,location_ip_master)
    # raise HTTPException(
    #         status_code=404,
    #         detail={"message": "Forwarder is not responding and the record deleted"}
    #
    #     )



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
        return


        # elif record_type == "MX":
        #     answers = resolver.resolve(zone, "MX")
        #     resolved_values = [str(answer.exchange).lower().rstrip('.') for answer in answers]
        #     #print(f"Resolved MX records: {resolved_values}")
        #     print('search for: ', record_value)
        #     if record_value.lower() in resolved_values:
        #         print(f"Domain {zone} has the expected MX record: {record_value}")
        #         return True
        #     else:
        #         print(f"Domain {zone} exists, but MX record does not match. Found: {resolved_values}")
        #         raise HTTPException(
        #             status_code=409,
        #             detail={"error":"The value is not correct"}
        #     )
        #

        # else:
        #     print ("Value didn't check")
        #
        #
    except:
        raise HTTPException(
            status_code=404,
            detail={"error": "value error"} ###TODO check
        )

