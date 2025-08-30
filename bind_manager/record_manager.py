import asyncio
import time
import httpx
from fastapi import HTTPException
import constants
import dns.query   #to use axfr
import dns.zone    #Access zone's data
import dns.update    #add record
import dns.tsigkeyring   #authenticate
import dns.resolver   #chech zone
import dns.rdatatype
import dns.reversename
import requests
from cryptography.fernet import Fernet
from bind_manager import checker
import ipaddress
import logging
from config.logging_config import setup_logging
from config.settings import settings

setup_logging()
logger = logging.getLogger(__name__)
keyring = dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET})

async def add_record(zone,new_record,new_record_type, new_record_value, ttl, priority, location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2) :
    checker.check_record_type(new_record_type)   ###Checking for correct type
    checker.zone_existance(zone,location_ip_master) ###Check if the zone exists in nameserver
    record_exist=checker.record_existance(zone,new_record,new_record_type, location_ip_master)
    if record_exist:
        raise HTTPException(
            status_code=404,
            detail={"error": "درخواست شما با خطا مواجه شد. دلیل: این رکورد با آدرس دیگری ثبت شده است "}
        )
    return await add_record_by_type(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2)

async def add_record_by_type(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder_1, location_ip_forwarder_2):
    func_name = f"add_{new_record_type}_record"
    await eval(f"{func_name}(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder_1, location_ip_forwarder_2)")

async def add_A_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2):
    """" Add A record and PTR record """
    try:
        ipaddress.IPv4Address(new_record_value)
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail={"error": " مقدار وارد شده درست نمیباشد", "value": new_record_value}
        )
    logger.info(f"Adding A record: {new_record} -> {new_record_value} in zone {zone}")
    await add_record_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2)
    ptr_zone = ".".join(new_record_value.split(".")[:3][::-1]) + ".in-addr.arpa"
    ptr_name = new_record_value.split(".")[-1]
    ptr_value=f"{new_record}.{zone}."
    logger.info(f"Adding PTR record: {ptr_name} -> {ptr_value} in zone {ptr_zone}")
    await add_record_func(ptr_zone,ptr_name,"PTR", ptr_value, ttl, location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2)
    logger.info(f"PTR record {ptr_name} successfully added to zone {ptr_zone}")

async def add_PTR_record(zone,new_record,new_record_type, new_record_value,ttl, location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2):
    logger.info(f"Attempting to add PTR record {new_record_value} in zone {zone}")
    PTR_LAST_OCTET_LIMIT =254
    if int(new_record) >= PTR_LAST_OCTET_LIMIT:
        logger.error(f"PTR record {new_record} exceeds limit {PTR_LAST_OCTET_LIMIT}")
        raise HTTPException(
            status_code=404,
            detail={"error": "درخواست شما با خطا مواجه شد. دلیل: مقدار رکورد بیشتر از 254 میباشد", "ptr_record": new_record}
        )
    ptr_records=get_all_ptr_records(zone, location_ip_master)
    targets_only = {target for _, target in ptr_records}  # use set for O(1) lookup
    if new_record_value in targets_only:
        logger.error(f"PTR record value {new_record_value} already exists in zone {zone}")
        raise HTTPException(
            status_code=404,
            detail={"error": "مقدار رکورد قبلا ثبت شده است.", "ptr_record": new_record_value}
        )
    logger.info(f"Adding PTR record {new_record_value} -> {new_record}.{zone}")
    await add_record_func(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder_1, location_ip_forwarder_2)
    logger.info(f"PTR record {new_record_value} successfully added to zone {zone}")

def get_all_ptr_records(zone_name, location_ip_master):
    """
    Return all PTR records as generator (full_name, target)
    """
    try:
        zone = dns.zone.from_xfr(
            dns.query.xfr(
                where=location_ip_master,
                zone=zone_name,
                keyring=dns.tsigkeyring.from_text({settings.KEY_NAME : settings.KEY_SECRET}),
                keyname=dns.name.from_text(settings.KEY_NAME),
                keyalgorithm=constants.key_algorithm
            )
        )
        return (
            (f"{name}.{zone.origin}", str(rdata.target))
            for name, node in zone.nodes.items()
            for rdataset in node.rdatasets
            if rdataset.rdtype == dns.rdatatype.PTR
            for rdata in rdataset
        )
    except Exception as e:
        logger.error(f"Zone transfer failed for {zone_name} from {location_ip_master}: {e}")
        return iter([])  # empty generator

async def add_AAAA_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2):
    logger.info(f"Attempting to add AAAA record {new_record_value} in zone {zone}")
    await add_record_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)
    logger.info(f"AAAA record {new_record_value} successfully added to zone {zone}")

async def add_TXT_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2):
    logger.info(f"Attempting to add TXT record {new_record_value} in zone {zone}")
    await add_record_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)
    logger.info(f"TXT record {new_record_value} successfully added to zone {zone}")

async def add_MX_record(zone,new_record, new_record_type,new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2 , mx_priority=10):
    print(zone,new_record,"A", new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2)
    await add_A_record(zone,new_record,"A", new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2)
    logger.info(f"A record {new_record_value} successfully added to zone {zone}")
    new_record_value=f"{mx_priority} {new_record}.{zone}."
    await add_record_func(zone,"@","MX", new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2)
    logger.info(f"MX record {new_record_value} successfully added to zone {zone}")

async def add_NS_record(zone, new_record, new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2):
    await add_record_func(zone, f"{new_record}", "A", new_record_value, ttl, location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)
    logger.info(f"A record {new_record_value} successfully added to zone {zone}")
    await add_record_func(zone, "@", "NS", f"{new_record}.{zone}.", ttl, location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)
    logger.info(f"NS record {new_record_value} successfully added to zone {zone}")

async def add_CNAME_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2):
    logger.info(f"CNAME record {new_record_value} successfully added to zone {zone}")
    await add_record_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)
    logger.info(f"CNAME record {new_record_value} successfully added to zone {zone}")
    return

async def add_record_func(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N=1):
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET}), keyalgorithm=constants.key_algorithm)
    update.add(new_record, ttl, new_record_type, new_record_value)
    response = dns.query.tcp(update, location_ip_master)
    if response.rcode() != dns.rcode.NOERROR:
        error_text = dns.rcode.to_text(response.rcode())
        raise HTTPException(
            status_code=403,
            detail={"error": f"DNS Update failed with rcode: {error_text}", "zone": zone}
        )
    run_apply(zone,location_ip_master)
    for location_ip_forwarder in [location_ip_forwarder_1 , location_ip_forwarder_2]:
        await add_record_with_forwarder_check(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2)

values_for_multiple_records = {}
async def add_record_with_forwarder_check(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N=1):

    values_for_multiple_records[new_record_type] = (
        zone,
        new_record,
        new_record_type,
        new_record_value,
        ttl,
        location_ip_master,
        location_ip_forwarder,
        location_ip_forwarder_1,
        location_ip_forwarder_2,
        check_forwarder_N
    )
    max_retry= 5
    while check_forwarder_N <= max_retry:
       logger.info(f"Forwarder checked for {check_forwarder_N} time(s)")
       if check_forwarder_N < max_retry-1:
            result = await  checker.check_forwarder_for_adding(zone, new_record, new_record_type, new_record_value, location_ip_master, location_ip_forwarder)
            if result == max_retry:
                check_forwarder_N = max_retry
                continue
            await wait_for_forwarder_reload(location_ip_forwarder, zone)
            check_forwarder_N += 1

       elif check_forwarder_N == max_retry-1:
             record_values = {new_record_type : values_for_multiple_records[new_record_type] for key in ["A", "PTR"]}
             if new_record_type == "MX":
                 delete_record_logic(record_values["A"][0], record_values["A"][1], record_values["A"][2],record_values["A"][3], record_values["A"][5],record_values["A"][6])
                 delete_record_logic(record_values["PTR"][0],record_values["PTR"][1], record_values["PTR"][2], record_values["PTR"][3], record_values["PTR"][5],record_values["PTR"][6])
                 delete_record_logic(record_values["MX"][0],record_values["MX"][1], record_values["MX"][2], record_values["MX"][3], record_values["MX"][5],record_values["MX"][6])
             elif new_record_type == "NS":
                 delete_record_logic(record_values["NS"][0], record_values["NS"][1], record_values["NS"][2], record_values["NS"][3], record_values["NS"][5], record_values["NS"][6])
                 delete_record_logic(record_values["A"][0], record_values["A"][1], record_values["A"][2], record_values["A"][3], record_values["A"][5], record_values["A"][6])
                 delete_record_logic(record_values["PTR"][0], record_values["PTR"][1], record_values["PTR"][2], record_values["PTR"][3], record_values["PTR"][5], record_values["PTR"][6])
             else:
                 delete_record_logic(zone, new_record, new_record_type, new_record_value, location_ip_master,location_ip_forwarder)
             raise HTTPException(
                  status_code=403,
                  detail={"error": "فرواردر و مستر سینک نیستند و رکورد حذف شد."}
                  )
       elif check_forwarder_N == max_retry:
            return None
    return None

def delete_record_logic (zone,record_name,record_type,record_value ,location_ip_master, location_ip_forwarder) :
    checker.check_record_type(record_type)
    checker.zone_existance(zone,location_ip_master)
    checker.record_existance_check_delete(zone ,record_name,record_type,record_value, location_ip_master)
    delete_record(zone,record_name,record_type,record_value,location_ip_master)

def delete_record(zone, new_record, new_record_type, record_value, location_ip_master):
        update = dns.update.Update(zone, keyring=keyring, keyalgorithm=constants.key_algorithm)
        record_value = record_value.strip()
        if record_value.endswith("."):
            record_value = record_value[:-1]
        if new_record_type == "MX" :
            # Query existing MX records
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [location_ip_master]
            fqdn = f"{new_record}.{zone}".replace("@.", "")
            answers = resolver.resolve(fqdn, "MX")
            current_mx = [r.to_text() for r in answers]  # Example: "10 mail-23.shirin.local."
            match = None
            for mx in current_mx:
                if record_value in mx:  # Match if value exists
                    match = mx
                    break
            if not match:
                return
            update.delete(new_record, "MX", match)
        elif new_record_type == "NS":
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [location_ip_master]
            fqdn = f"{new_record}.{zone}".replace("@.", "")
            answers = resolver.resolve(fqdn, "NS")
            current_NS = [r.to_text() for r in answers]
            match = None
            for NS in current_NS:
                if record_value in NS:  # Match if value exists
                    match =NS
                    break
            if not match:
                return
            update.delete(new_record, "NS", match)
        elif new_record_type == "PTR":
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [location_ip_master]
            fqdn = f"{new_record}.{zone}"
            answers = resolver.resolve(fqdn, "PTR")
            current_ptr = [r.to_text() for r in answers]
            match = None
            for ptr in current_ptr:
                if record_value.rstrip(".") == ptr.rstrip("."):
                    match = ptr
                    break
            if not match:
                return
            update.delete(new_record, "PTR", match)
            dns.query.tcp(update, location_ip_master)
        elif new_record_type == "CNAME":
            fqdn = f"{new_record}.{zone}.".lower()
            update.delete(fqdn, "CNAME")  # Delete entire RRset
        else:
            update.delete(new_record, new_record_type)
            dns.query.tcp(update, location_ip_master)
        run_apply(zone, location_ip_master)

async def del_record_for_deletation(zone, new_record, new_record_type, record_value, location_ip_master):
    update = dns.update.Update(zone, keyring=keyring, keyalgorithm=constants.key_algorithm)
    record_value = record_value.strip()
    if new_record_type == "NS":
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_master]
        #fqdn = f"{new_record}.{zone}".replace("@.", "")
        answers = resolver.resolve( zone, "NS")
        current_NS = [r.to_text() for r in answers]
        match = None
        for NS in current_NS:
            if record_value in NS:  # Match if value exists
                match = NS
                break
        if not match:
            return
        update.delete(new_record, "NS", match)
    elif new_record_type == "CNAME":
        fqdn = f"{new_record}.{zone}.".lower()
        update.delete(fqdn, "CNAME")  # Delete entire RRset
    elif new_record_type == "PTR":
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_master]
        fqdn =f"{new_record}.{zone}"
        answers = resolver.resolve(fqdn , "PTR")
        current_ptr = [r.to_text() for r in answers]
        match = None
        for ptr in current_ptr:
            if record_value.rstrip(".") == ptr.rstrip("."):
                match = ptr
                break
        if not match:
            return
    elif new_record_type == "MX":
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_master]
        fqdn = f"{new_record}".replace("@.", "")
        answers = resolver.resolve(fqdn, "MX")
        current_mx = [r.to_text() for r in answers]
        match = None
        for mx in current_mx:
            if record_value in mx:
                match = mx
                break
        if not match:
            raise HTTPException(
                status_code=404,
                detail={"error": "رکورد MX با این مقدار وجود ندارد",}
            )
        update.delete(new_record, "MX", match)
    else:
        update.delete(new_record, new_record_type)
    response = dns.query.tcp(update, location_ip_master)
    if response.rcode() != dns.rcode.NOERROR:
        error_text = dns.rcode.to_text(response.rcode())
        raise HTTPException(
            status_code=403,
            detail={"error": f"DNS Update failed with rcode: {error_text}", "zone": zone}
        )
    else:
        run_apply(zone, location_ip_master)

def update_record(zone,record_name,record_type,  new_record_value,record_value,ttl, location_ip_master,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N=1):
                 # zone, record_name, record_type, second_value, record_value, ttl, location_ip_master, location_ip_forwarder_1, location_ip_forwarder_2
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET}), keyalgorithm=constants.key_algorithm)
    if record_type == "MX":
        query = dns.message.make_query(record_value, dns.rdatatype.from_text("A"))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_master, timeout=3)
        except Exception as e:
            print(e)
            response = None

        if response and response.answer:
            resolved_ips = [str(item) for answer in response.answer for item in answer.items]
            update.delete(record_value,"A")
            response = dns.query.tcp(update, location_ip_master)
            run_apply(zone, location_ip_master)
            update.add(new_record_value,ttl,"A",resolved_ips[0])
            response = dns.query.tcp(update, location_ip_master)
            run_apply(zone, location_ip_master)
            #update.replace(record_name, ttl, record_type, new_record_value)

        del_record_for_deletation(zone, record_name, record_type, record_value, location_ip_master)
        mx_priority = "10"
        new_record_value = f"{mx_priority} {new_record_value}"
        add_record_func(zone, "@", record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)

    if record_type == "NS":
        query = dns.message.make_query(record_value, dns.rdatatype.from_text("A"))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_master, timeout=3)
        except Exception as e:
            print(e)
            response = None

        if response and response.answer:
            resolved_ips = [str(item) for answer in response.answer for item in answer.items]
            print(record_name)
            print(resolved_ips)
            print(record_value)
            del_record_for_deletation(zone, record_name, record_type, record_value, location_ip_master)
            update.delete(record_value, "A")
            response = dns.query.tcp(update, location_ip_master)
            print(response)
            run_apply(zone, location_ip_master)
            print (new_record_value)
            print(resolved_ips[0])
            update.add(new_record_value, ttl, "A", resolved_ips[0])
            response = dns.query.tcp(update, location_ip_master)
            print(response)
            run_apply(zone, location_ip_master)
            add_record_func(zone, "@", record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder_1,
                            location_ip_forwarder_2)


        #add_record_func(zone, "@", record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)
    else:
        update.replace(record_name, ttl, record_type, new_record_value)
        response = dns.query.tcp(update, location_ip_master)
        print(response)
    run_apply(zone,location_ip_master)
    for location_ip_forwarder in [location_ip_forwarder_1 , location_ip_forwarder_2]:
        add_record_with_forwarder_check(zone, record_name, record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1, location_ip_forwarder_2 )

async def del_record(zone,record_name,record_type, record_value, ttl, priority, location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2):
    checker.check_record_type(record_type)
    checker.zone_existance(zone,location_ip_master )
    checker.record_existance_check_delete(zone ,record_name,record_type,record_value, location_ip_master)
    await del_record_for_deletation(zone,record_name,record_type,record_value,location_ip_master)
    for location_ip_forwarder in [location_ip_forwarder_1 , location_ip_forwarder_2]:
        await check_forwarder_after_deletation(zone, record_name, record_type, record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2)

async def check_forwarder_after_deletation(zone, record_name, record_type, record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N=1):
    max_retry=10
    while check_forwarder_N <= max_retry:
        if check_forwarder_N < max_retry:
            result =await checker.check_forwarder_del(zone, record_name, record_type, record_value, location_ip_master, location_ip_forwarder)
            if result == max_retry:
                check_forwarder_N = max_retry  # success, go on
                continue
            await wait_for_forwarder_reload(location_ip_forwarder, zone)
            check_forwarder_N += 1
        elif check_forwarder_N == max_retry-1:
             raise HTTPException(
                  status_code=403,
                  detail={"error": "فرواردر ها با مستر سینک نشده اند."}
                  )
        elif check_forwarder_N == max_retry:
            if record_type == "A":
                ptr_zone = ".".join(record_value.split(".")[:3][::-1]) + ".in-addr.arpa"
                ptr_name = record_value.split(".")[-1]
                ptr_value=f"{record_name}.{zone}."
                await del_record_for_deletation(ptr_zone,ptr_name,"PTR", ptr_value, location_ip_master)
                return
            else:
                return




def update_record_progress(zone,record_name,record_type,record_value,second_value,ttl,priority,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2,check_forwarder_N=1):
    correct_type =checker.check_record_type(record_type)
    checker.zone_existance(zone, location_ip_master)
    checker.record_existance_check_delete(zone ,record_name,record_type,record_value, location_ip_master)
    update_record(zone,record_name,record_type,second_value,record_value,ttl,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2)
    if record_type == "A":
        ptr_zone = ".".join(second_value.split(".")[:3][::-1]) + ".in-addr.arpa"
        ptr_name = record_value.split(".")[-1]
        ptr_value = f"{record_name}.{zone}."
        delete_record_logic(ptr_zone, ptr_name, "PTR", ptr_value, location_ip_master, location_ip_forwarder_1)
        #update_record_progress(ptr_zone,ptr_name,record_type,ptr_value,ptr_second_value,ttl,priority,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2 ,check_forwarder_N=1)



def run_apply(zone, location_ip_master):
    api1_url = f"http://{location_ip_master}:8000/{zone}/apply/"
    cipher_suite = Fernet(settings.fernet_key.encode())
    token = cipher_suite.encrypt(settings.client_ip.encode()).decode()

    headers = {"token": token}
    try:
        r = requests.get(api1_url, headers=headers, timeout=5)
        logger.info(f"Running apply command for zone {zone} on master {location_ip_master}")
    except requests.RequestException as e:
        logger.error(f"Master apply failed for zone {zone} - {e}")
        raise HTTPException(status_code=403, detail={"error": "The master did not update"})


# def trigger_reload(zone, location_ip_forwarder):
#     api2_url = f"http://{location_ip_forwarder}:8000/{zone}/reload/"
#     cipher_suite = Fernet(settings.fernet_key.encode())
#     token = cipher_suite.encrypt(settings.client_ip.encode()).decode()
#
#     headers = {"token": token}
#     try:
#         r = requests.get(api2_url, headers=headers, timeout=5)
#         logger.info(f"Reload triggered for zone {zone} on forwarder {location_ip_forwarder}")
#     except requests.RequestException as e:
#         logger.error(f"Forwarder reload failed for zone {zone} - {e}")
#         raise HTTPException(status_code=403, detail={"error": "Forwarder did not reload"})


async def wait_for_forwarder_reload(forwarder_ip: str, zone: str, timeout: int = 30):
    cipher_suite = Fernet(settings.fernet_key.encode())
    token = cipher_suite.encrypt(settings.client_ip.encode()).decode()
    headers = {"token": token}

    api_reload_url = f"http://{forwarder_ip}:8000/{zone}/reload/"

    async with httpx.AsyncClient() as client:
        # Trigger reload
        try:
            r = await client.post(api_reload_url, headers=headers, timeout=5)
            r.raise_for_status()
        except httpx.RequestError as e:
            logger.error(f"Failed to contact forwarder {forwarder_ip}: {e}")
            raise HTTPException(status_code=503, detail=f"Forwarder not reachable: {forwarder_ip}")
        except httpx.HTTPStatusError as e:
            logger.error(f"Forwarder reload request failed: {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)

        logger.info(f"Reload triggered for zone {zone} on forwarder {forwarder_ip}")

        # Polling loop to check status
        status_url = f"http://{forwarder_ip}:8000/{zone}/reload/status/"
        start_time = asyncio.get_event_loop().time()

        while True:
            if asyncio.get_event_loop().time() - start_time > timeout:
                raise HTTPException(status_code=504, detail="Timeout waiting for forwarder reload")

            try:
                r_status = await client.get(status_url, headers=headers, timeout=5)
                r_status.raise_for_status()
                status = r_status.json().get("status")
            except Exception as e:
                logger.warning(f"Error checking reload status for {forwarder_ip}: {e}")
                await asyncio.sleep(1)
                continue
            logger.info(f"The status of reloading forwarder is: {status}")
            if status == "done":
                logger.info(f"Forwarder {forwarder_ip} finished reloading zone {zone}")
                return True
            elif status == "error":
                raise HTTPException(status_code=500, detail=f"Forwarder failed reloading zone {zone}")

            await asyncio.sleep(1)