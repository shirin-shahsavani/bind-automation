import asyncio
import logging
import httpx
from cryptography.fernet import Fernet
from fastapi import HTTPException
import constants
import dns.query   #to use axfr
import dns.zone    #Access zone's data
import dns.tsigkeyring   #authenticate
import dns.resolver   #chech zone
import dns.rdatatype
import ipaddress
from dns.rdtypes.ANY.MX import MX
import time
from config.settings import settings

logger = logging.getLogger(__name__)
keyring = dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET})

def check_record_type(record_type):
    if record_type not in ["A","AAAA", "NS" ,"MX","CNAME", "TXT", "PTR"]:
        raise HTTPException(
            status_code=404,
            detail={"error": "درخواست شما با خطا مواجه شد. دلیل: اشتباه در ثبت تایپ رکورد", "type": record_type}
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
            detail={"error": "درخواست شما با خطا مواجه شد. دلیل: این زون وجود ندارد و یا در دسترس نمیباشد", "zone": zone}
        )



def record_existance(zone,new_record,new_record_type,location_ip_master):
    global keyring
    print(new_record_type)
    if new_record_type == "PTR":
        return False

    elif new_record_type == "NS":
        new_ns_record = f"{new_record}.{zone}."
        keyring = dns.tsigkeyring.from_text({constants.key_name: constants.key_secret})
        try:
            zone_data = dns.zone.from_xfr(dns.query.xfr(location_ip_master, zone, keyring=keyring, keyname=dns.name.from_text(constants.key_name),keyalgorithm=constants.key_algorithm))
        except Exception as e:
            print(f"AXFR failed: {e}")
            return False
        for name, node in zone_data.nodes.items():
            for rdataset in node.rdatasets:
                record_type = dns.rdatatype.to_text(rdataset.rdtype)
                if str(f"{name}.{zone}.") == new_ns_record:
                    print("NS record already exists")
                    #record_found = True
                    return True

    else :
        """Retrieve zone data via AXFR transfer."""
        #keyring = dns.tsigkeyring.from_text({constants.key_name: constants.key_secret})
        zone_data = dns.zone.from_xfr(dns.query.xfr(location_ip_master, zone, keyring=keyring, keyname=settings.KEY_NAME))
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

    zone_data = dns.zone.from_xfr(dns.query.xfr(location_ip_master, zone, keyring=keyring, keyname=constants.key_name))

    if new_record_type in ["MX" , "NS"]:
        #dns_server = location_ip_master
        resolver = location_ip_master.Resolver()
        resolver.nameservers = [location_ip_master]
        attr_map = {"MX": "exchange", "NS": "target"}
        try:
            answers = resolver.resolve(zone, new_record_type)
            for rdata in answers:
                value_in_server = str(getattr(rdata, attr_map[new_record_type])).rstrip('.')
                if value_in_server.lower() == record_value.rstrip('.').lower():
                    return True
            return False
        except Exception as e:
            logger.warning(f"Error checking {new_record_type}: {e}")
            return False
    else:
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
                status_code=404,
                detail={"error":"درخواست حذف رکورد شما با ارور مواجه شد. "
                                "دلیل:عدم وجود رکورد"}
        )


# async def check_forwarder_add(zone, new_record, new_record_type, new_record_value, location_ip_master, location_ip_forwarder):
#         if new_record_type in ["A" , "AAAA","TXT"]:
#             fqdn = f"{new_record}.{zone}"
#             query = dns.message.make_query(fqdn, dns.rdatatype.from_text(new_record_type))
#             query.flags |= dns.flags.RD  # Recursion Desired flag
#             resolved_ips = []
#             try:
#                 response = dns.query.udp(query, location_ip_forwarder, timeout=3)
#             except Exception as e:
#                 print(e)
#                 response = None
#
#             if response and response.answer:
#                 resolved_ips = [str(item) for answer in response.answer for item in answer.items]
#             if new_record_type == "A":
#                 #await wait_for_forwarder_reload (location_ip_forwarder, zone)
#                 if new_record_value in resolved_ips:
#                     check_forwarder_N = 10
#                     return check_forwarder_N
#                 else:
#                     print(f"Domain {fqdn} exists, but IP does not match. Found: {resolved_ips}")
#             if new_record_type == "AAAA":
#                 try:
#                     expected_ip = ipaddress.IPv6Address(new_record_value)
#                     normalized_resolved = [ipaddress.IPv6Address(ip) for ip in resolved_ips]
#
#
#                     if expected_ip in normalized_resolved:
#                         check_forwarder_N = 10
#                         return check_forwarder_N
#                     else:
#                         print(f"Domain {fqdn} exists, but IP does not match. Found: {resolved_ips}")
#
#                 except Exception as e:
#                     print(f"Invalid IPv6 address provided: {e}")
#             if new_record_type == "TXT":
#                 time.sleep(2)
#                 expected_txt = new_record_value.strip('"')
#                 found_txt_records = [item.strip('"') for item in resolved_ips]
#
#                 if expected_txt in found_txt_records:
#                     check_forwarder_N = 10
#                     return check_forwarder_N
#                 else:
#                     print(f"TXT record {fqdn} exists, but value does not match. Found: {found_txt_records}")
#
#         if new_record_type in ["PTR"]:
#             PTR_record=f"{new_record}.{zone}"
#             query = dns.message.make_query(PTR_record, dns.rdatatype.from_text(new_record_type))
#             query.flags |= dns.flags.RD
#             resolved_ips = []
#             try:
#                response = dns.query.udp(query, location_ip_forwarder, timeout=3)
#             except Exception as e:
#                  print(f"DNS query failed: {e} . forwarder does not available")
#                  response = None
#
#             if response and response.answer:
#                 for answer in response.answer:
#                     for item in answer.items:
#                         resolved_ips.append(str(item))
#             suffix =  f".{zone}."
#             cleaned = [name.removesuffix(suffix) for name in resolved_ips]
#             if new_record_value in cleaned:
#                 check_forwarder_N = 10
#                 return check_forwarder_N
#             else:
#                 print(f"Domain {PTR_record} exists, but IP does not match. Found: {cleaned}")
#         if new_record_type in ["MX"] :
#             time.sleep(10)
#             dns_server = location_ip_forwarder
#             resolver = dns.resolver.Resolver()
#             resolver.nameservers = [dns_server]
#             mx_value=[]
#             try:
#                 answers = resolver.resolve(zone, "MX")
#                 for rdata in answers:
#                     rdata: MX
#                     mx_record_in_server = str(rdata.exchange).rstrip('.')
#                     new_record_value = new_record_value.split()[1].rstrip('.')
#                     mx_value.append(new_record_value)
#                     if mx_record_in_server.lower() == new_record_value.lower():
#                         check_forwarder_N = 10
#                         return check_forwarder_N
#                     else:
#                         print("we don't have", new_record_value)
#                         break
#
#                 return False
#             except Exception as e:
#                 print(f"Error checking MX: {e}")
#                 return False
#
#         if new_record_type == "NS":
#             time.sleep(10)
#             dns_server = location_ip_forwarder
#             resolver = dns.resolver.Resolver()
#             resolver.nameservers = [dns_server]
#             try:
#                 answers = resolver.resolve(zone, "NS")
#                 ns_list = [str(rdata.target).rstrip('.') for rdata in answers]
#                 expected_ns = new_record_value.rstrip('.')
#                 if expected_ns in ns_list:
#                     check_forwarder_N = 10
#                     return check_forwarder_N
#                 else:
#                     return False
#             except Exception as e:
#                 print(f"Error checking NS: {e}")
#             return False
#
#         if new_record_type == "CNAME":
#             time.sleep(10)
#             fqdn = f"{new_record}.{zone}".rstrip('.')
#             try:
#                 resolver = dns.resolver.Resolver()
#                 resolver.nameservers = [location_ip_forwarder]
#                 answers = resolver.resolve(fqdn, "CNAME")
#                 resolved_target = str(answers[0].target).rstrip('.')
#             except dns.resolver.NoAnswer:
#                 resolved_target = None
#             except dns.resolver.NXDOMAIN:
#                 resolved_target = None
#             except Exception as e:
#                 print(f"Error querying CNAME: {e}")
#                 resolved_target = None
#
#             expected_cname = new_record_value.rstrip('.')
#
#             if resolved_target and resolved_target.lower() == expected_cname.lower():
#                 check_forwarder_N = 10
#                 return check_forwarder_N
#             else:
#                 if resolved_target is None:
#                     return False

#        return None


async def check_forwarder_for_adding(zone, new_record, new_record_type, new_record_value, location_ip_master, location_ip_forwarder):
    if new_record_type in ["A", "AAAA", "TXT"]:
        fqdn = f"{new_record}.{zone}"
        query = dns.message.make_query(fqdn, dns.rdatatype.from_text(new_record_type))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_forwarder, timeout=3)
        except Exception as e:
            logger.warning (e)
            response = None

        if response and response.answer:
            resolved_ips = [str(item) for answer in response.answer for item in answer.items]
        if new_record_type == "A":
            if new_record_value in resolved_ips:
                check_forwarder_N = 10
                return check_forwarder_N
        elif new_record_type == "AAAA":
            try:
                expected_ip = ipaddress.IPv6Address(new_record_value)
                normalized_resolved = [ipaddress.IPv6Address(ip) for ip in resolved_ips]
                if expected_ip in normalized_resolved:
                    check_forwarder_N = 10
                    return check_forwarder_N
            except Exception as e:
                logger.warning(f"Invalid IPv6 address provided: {e}")
        elif new_record_type == "TXT":
            expected_txt = new_record_value.strip('"')
            found_txt_records = [item.strip('"') for item in resolved_ips]
            if expected_txt in found_txt_records:
                check_forwarder_N = 10
                return check_forwarder_N
    elif new_record_type in ["PTR"]:
        PTR_record = f"{new_record}.{zone}"
        query = dns.message.make_query(PTR_record, dns.rdatatype.from_text(new_record_type))
        query.flags |= dns.flags.RD
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_forwarder, timeout=3)
        except Exception as e:
            logger.warning(f"DNS query failed: {e} . forwarder does not available")
            response = None
        if response and response.answer:
            for answer in response.answer:
                for item in answer.items:
                    resolved_ips.append(str(item))
        suffix = f".{zone}."
        cleaned = [name.removesuffix(suffix) for name in resolved_ips]
        if new_record_value in cleaned:
            check_forwarder_N = 10
            return check_forwarder_N
    if new_record_type in ["MX"]:
        dns_server = location_ip_forwarder
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        mx_value = []
        try:
            answers = resolver.resolve(zone, "MX")
            for rdata in answers:
                rdata: MX
                mx_record_in_server=str(rdata.exchange).rstrip('.')
                new_record_value = new_record_value.split()[1].rstrip('.')
                mx_value.append(new_record_value)
                if mx_record_in_server.lower() == new_record_value.lower():
                    check_forwarder_N = 10
                    return check_forwarder_N
                else:
                    break
            return False
        except Exception as e:
            logger.warning(f"Error checking MX: {e}")
            return False

    if new_record_type == "NS":
        dns_server = location_ip_forwarder
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        try:
            answers = resolver.resolve(zone, "NS")
            ns_list = [str(rdata.target).rstrip('.') for rdata in answers]
            expected_ns = new_record_value.rstrip('.')
            if expected_ns in ns_list:
                check_forwarder_N = 10
                return check_forwarder_N
            else:
                return False
        except Exception as e:
            logger.warning(f"Error checking NS: {e}")
        return False

    if new_record_type == "CNAME":
        fqdn = f"{new_record}.{zone}."###########.rstrip('.')
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [location_ip_forwarder]
            answers = resolver.resolve(fqdn, "CNAME")
            resolved_target = str(answers[0].target).rstrip('.')
        except dns.resolver.NoAnswer:
            resolved_target = None
        except dns.resolver.NXDOMAIN:
            resolved_target = None
        except Exception as e:
            logger.warning(f"Error querying CNAME: {e}")
            resolved_target = None
        expected_cname = new_record_value.rstrip('.')
        if resolved_target and resolved_target.lower() == expected_cname.lower():
            check_forwarder_N = 10
            return check_forwarder_N
        else:
            if resolved_target is None:
                return False
    return None


def check_forwarder_del(zone, new_record, record_type, record_value, location_ip_master, location_ip_forwarder):
    time.sleep(10)
    if record_type in ["A", "AAAA","TXT"]:
        fqdn = f"{new_record}.{zone}"
        query = dns.message.make_query(fqdn, dns.rdatatype.from_text(record_type))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_forwarder, timeout=3)
        except Exception as e:
            print(f"DNS query failed: {e} . forwarder does not available")
            response = None

        resolved_ips = [str(item) for answer in response.answer for item in answer.items]
        if record_type == "A":
            if record_value not in resolved_ips:
                check_forwarder_N = 10
                return check_forwarder_N
            else:
                print(f"Record {fqdn} is still exist. Found: {resolved_ips}")
        if record_type == "AAAA":
            try:
                if record_value not in resolved_ips:
                    check_forwarder_N = 10
                    return check_forwarder_N
                else:
                    print(f"Record {fqdn} is still exist. Found: {resolved_ips}")

            except Exception as e:
                print(f"Invalid IPv6 address provided: {e}")

        if record_type == "TXT":
            time.sleep(5)
            expected_txt = record_value.strip('"')
            found_txt_records = [item.strip('"') for item in resolved_ips]

            if expected_txt not in found_txt_records:
                check_forwarder_N = 10
                return check_forwarder_N

    if record_type == "PTR":
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_forwarder]
        fqdn = f"{new_record}.{zone}"
        answers = resolver.resolve(fqdn, "PTR")

        current_ptr = [r.to_text() for r in answers]
        match = None
        for ptr in current_ptr:
            if record_value.rstrip(".") == ptr.rstrip("."):
                match = ptr
                break
        if not match:
            check_forwarder_N = 10
            return check_forwarder_N

    if record_type in ["MX"]:
        time.sleep(5)
        dns_server = location_ip_forwarder
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        mx_value = []
        try:
            answers = resolver.resolve(zone, "MX")
            for rdata in answers:
                rdata: MX
                mx_record_in_server = str(rdata.exchange).rstrip('.')
                new_record_value = record_value    ##.split()[1].rstrip('.')
                mx_value.append(new_record_value)
                if mx_record_in_server.lower() != new_record_value.lower():
                    check_forwarder_N = 10
                    return check_forwarder_N
                else:
                    break

            return False
        except Exception as e:
            print(f"Error checking MX: {e}")
            return False

    if record_type == "NS":
        time.sleep(10)
        dns_server = location_ip_forwarder
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        try:
            answers = resolver.resolve(zone, "NS")
            ns_list = [str(rdata.target).rstrip('.') for rdata in answers]
            expected_ns = record_value.rstrip('.')
            if expected_ns not in ns_list:
                check_forwarder_N = 10
                return check_forwarder_N
            else:
                print("it still exist")
        except Exception as e:
            print(f"Error checking NS: {e}")
        return False

    if record_type == "CNAME":
        time.sleep(5)
        fqdn = f"{new_record}.{zone}".rstrip('.')
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_forwarder]
        try:
            answers = resolver.resolve(fqdn, "CNAME", raise_on_no_answer=False)
            # Handle case: the domain exists, but has no CNAME
            if not answers.rrset:
                resolved_target = None
                check_forwarder_N = 10
                return check_forwarder_N
            # Got a CNAME
            resolved_target = str(answers[0].target).rstrip('.')
        except dns.resolver.NXDOMAIN:
            print(f"{fqdn} does not exist in DNS.")
            resolved_target = None
            check_forwarder_N = 10
            return check_forwarder_N
        except Exception:
            resolved_target = None
            check_forwarder_N = 10
            return check_forwarder_N
        # Compare resolved target with expected CNAME
        expected_cname = record_value.rstrip('.')
        if resolved_target and resolved_target.lower() != expected_cname.lower():
            check_forwarder_N = 10
            return check_forwarder_N
        else:
            if resolved_target is None:
                return False
    return None


def check_the_value(zone,record_name,record_type, record_value,location_ip_master):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [location_ip_master]
    if record_type == "MX":
        # Extract only the hostname part (after priority) and strip trailing dot
        record_value = record_value.split()[1].rstrip('.')

    try:
        if record_type in ["A" ,"AAAA" , "TXT","MX","CNAME","PTR"] :
            fqdn = f"{record_name}.{zone}".lower()
            answers = resolver.resolve(fqdn,record_type)
            resolved_ips = [str(answer) for answer in answers]
            resolved_ips=str(resolved_ips)
            if record_type == "MX":
                # Compare against MX exchange names
                resolved_hosts = [str(answer.exchange).rstrip('.') for answer in answers]
                if record_value in resolved_hosts:
                    return True
                else:
                    raise HTTPException(status_code=409, detail={"error": "MX does not match"})
            if record_value in resolved_ips:
                return True
            elif record_value not in resolved_ips:
                raise HTTPException(
                    status_code=409,
                    detail={"error":"Ip does not match"}
            )
        return None

    except:
        raise HTTPException(
            status_code=404,
            detail={"error": "درخواست حذف رکورد شما با ارور مواجه شد. دلیل: رکورد با آدرس دیگری ثبت شده است."} ###TODO check
        )



# async def wait_for_forwarder_reload(forwarder_ip: str, zone: str , timeout: int = 30):
#     # async def wait_for_forwarder_reload(forwarder_ip: str, zone: str, timeout: int = 30):
#         cipher_suite = Fernet(settings.fernet_key.encode())
#         token = cipher_suite.encrypt(settings.client_ip.encode()).decode()
#         headers = {"token": token}
#
#         api_reload_url = f"http://{forwarder_ip}:8000/{zone}/reload/"
#         print(api_reload_url)
#
#         async with httpx.AsyncClient() as client:
#             # Trigger reload
#             try:
#                 r = await client.post(api_reload_url, headers=headers, timeout=5)
#                 r.raise_for_status()
#             except httpx.RequestError as e:
#                 logger.error(f"Failed to contact forwarder {forwarder_ip}: {e}")
#                 raise HTTPException(status_code=503, detail=f"Forwarder not reachable: {forwarder_ip}")
#             except httpx.HTTPStatusError as e:
#                 logger.error(f"Forwarder reload request failed: {e.response.text}")
#                 raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
#
#             job_id = r.json().get("job_id")
#             if not job_id:
#                 raise HTTPException(status_code=500, detail="Forwarder did not return a job ID")
#
#             logger.info(f"Reload triggered for zone {zone} on forwarder {forwarder_ip}, job_id={job_id}")
#
#             # Polling loop to check status
#             status_url = f"http://{forwarder_ip}:8000/{zone}/reload/status/{job_id}"
#             start_time = asyncio.get_event_loop().time()
#
#             while True:
#                 if asyncio.get_event_loop().time() - start_time > timeout:
#                     raise HTTPException(status_code=504, detail="Timeout waiting for forwarder reload")
#
#                 try:
#                     r_status = await client.get(status_url, headers=headers, timeout=5)
#                     r_status.raise_for_status()
#                     status = r_status.json().get("status")
#                 except Exception as e:
#                     logger.warning(f"Error checking reload status for {forwarder_ip}: {e}")
#                     await asyncio.sleep(1)
#                     continue
#
#                 if status == "done":
#                     logger.info(f"Forwarder {forwarder_ip} finished reloading zone {zone}")
#                     return True
#
#                 await asyncio.sleep(1)
