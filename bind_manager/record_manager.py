import time
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



def add_record(zone,new_record,new_record_type, new_record_value, ttl, priority, location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2) :
    checker.check_record_type(new_record_type)   ###Checking for correct type
    checker.zone_existance(zone,location_ip_master) ###Check if the zone exists in nameserver
    record_exist=checker.record_existance(zone,new_record,new_record_type, location_ip_master)
    if record_exist:
        raise HTTPException(
            status_code=404,
            detail={"error": "درخواست شما با خطا مواجه شد. دلیل: این رکورد با آدرس دیگری ثبت شده است "}
        )
    return add_record_by_type(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2)

def add_record_by_type(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder_1, location_ip_forwarder_2):
    func_name = f"add_{new_record_type}_record"
    eval(f"{func_name}(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master, location_ip_forwarder_1, location_ip_forwarder_2)")

def add_A_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2):
    """" Add A record and PTR record """
    try:
        ipaddress.IPv4Address(new_record_value)
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail={"error": " مقدار وارد شده درست نمیباشد", "value": new_record_value}
        )
    add_record_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2)
    ptr_zone = ".".join(new_record_value.split(".")[:3][::-1]) + ".in-addr.arpa"
    ptr_name = new_record_value.split(".")[-1]
    ptr_value=f"{new_record}.{zone}."
    add_record_func(ptr_zone,ptr_name,"PTR", ptr_value, ttl, location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2)


def add_record_func(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N=1):
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}), keyalgorithm=constants.key_algorithm)
    update.add(new_record, ttl, new_record_type, new_record_value)
    response = dns.query.tcp(update, location_ip_master)
    print(response)
    if response.rcode() != dns.rcode.NOERROR:
        error_text = dns.rcode.to_text(response.rcode())
        raise HTTPException(
            status_code=403,
            detail={"error": f"DNS Update failed with rcode: {error_text}", "zone": zone}
        )
    run_apply(zone,location_ip_master)
    for location_ip_forwarder in [location_ip_forwarder_1 , location_ip_forwarder_2]:
        update_record_with_forwarder_check(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2)

values_for_multiple_records={}

def update_record_with_forwarder_check(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N=1):

    if new_record_type == "A":
        values_for_multiple_records["A"]=(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N)
    if new_record_type == "PTR":
        values_for_multiple_records["PTR"]=(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N)
    if new_record_type == "MX":
        values_for_multiple_records["MX"]=(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N)
    if new_record_type == "NS":
        values_for_multiple_records["NS"]=(zone,new_record,new_record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N)

    if new_record_type in ["A","AAAA" , "PTR" , "MX" , "NS" , "CNAME","TXT"]:
        while check_forwarder_N <= 10:
           print(check_forwarder_N)
           if check_forwarder_N < 9:
                result = checker.check_forwarder_for_updating(zone, new_record, new_record_type, new_record_value, location_ip_master, location_ip_forwarder)
                if result == 10:
                    check_forwarder_N = 10
                    continue
                trigger_reload(zone,location_ip_forwarder)
                check_forwarder_N += 1

           elif check_forwarder_N == 9:
                 # if new_record_type == "MX":
                 #     A_value = values_for_multiple_records['A']
                 #     ptr_value = values_for_multiple_records['PTR']
                 #     MX_value = values_for_multiple_records['MX']
                 #     delete_record_logic(MX_value[0],MX_value[1],MX_value[2], MX_value[3], MX_value[5],MX_value[6] )
                 #     delete_record_logic(ptr_value[0], ptr_value[1], ptr_value[2], ptr_value[3], ptr_value[5],ptr_value[6])
                 #     delete_record_logic(A_value[0], A_value[1], A_value[2], A_value[3], A_value[5], A_value[6])
                 # elif new_record_type == "NS":
                 #     A_value = values_for_multiple_records['A']
                 #     NS_value = values_for_multiple_records['NS']
                 #     ptr_value = values_for_multiple_records['PTR']
                 #     delete_record_logic(NS_value[0], NS_value[1], NS_value[2], NS_value[3], NS_value[5], NS_value[6])
                 #     delete_record_logic(ptr_value[0], ptr_value[1], ptr_value[2], ptr_value[3], ptr_value[5],ptr_value[6])
                 #     delete_record_logic(A_value[0], A_value[1], A_value[2], A_value[3], A_value[5], A_value[6])
                 # else:
                 #     delete_record_logic(zone, new_record, new_record_type, new_record_value, location_ip_master,location_ip_forwarder)
                 raise HTTPException(
                      status_code=403,
                      detail={"error": "فرواردر و مستر سینک نیستند و رکورد حذف شد."}
                      )

           elif check_forwarder_N == 10:
                if new_record_type == "A":
                    ptr_zone = ".".join(new_record_value.split(".")[:3][::-1]) + ".in-addr.arpa"
                    ptr_name = new_record_value.split(".")[-1]
                    ptr_value=f"{new_record}.{zone}."
                    update = dns.update.Update(ptr_zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}), keyalgorithm=constants.key_algorithm)
                    update.add(ptr_name, ttl, "PTR", ptr_value)
                    dns.query.tcp(update, location_ip_master)
                    values_for_multiple_records["PTR"] = (ptr_zone, ptr_name, "PTR", ptr_value, ttl,location_ip_master, location_ip_forwarder,location_ip_forwarder_1, location_ip_forwarder_2,check_forwarder_N)
                    run_apply(ptr_zone, location_ip_master)
                    break
                elif new_record_type in ["AAAA" , "PTR" , "MX" , "NS" , "CNAME","TXT"]:
                    return None
        return None
    return None

def delete_record_logic (zone,record_name,record_type,record_value ,location_ip_master, location_ip_forwarder) :
    correct_type = checker.check_record_type(record_type)
    zone_exists=checker.zone_existance(zone,location_ip_master)
    checker.record_existance_check_delete(zone ,record_name,record_type,record_value, location_ip_master)
    delete_record(zone,record_name,record_type,record_value,location_ip_master)



def add_PTR_record(zone,new_record,new_record_type, new_record_value,ttl, location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2):
    if int(new_record) >= 255:
        raise HTTPException(
            status_code=404,
            detail={"error": "درخواست شما با خطا مواجه شد. دلیل: مقدار رکورد بیشتر از 254 میباشد", "ptr_record": new_record}
        )
    ptr_records=get_all_ptr_records(zone, location_ip_master)
    targets_only = [record[1] for record in ptr_records]
    if new_record_value in targets_only:
        raise HTTPException(
                status_code=404,
                detail={"error":"درخواست شما با خطا مواجه شد. دلیل: مقدار رکورد وجود دارد"}
        )
    else:
        add_record_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2)
        return

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
                        ptr_records.append((full_name, str(rdata.target)))
        return ptr_records
    except Exception as e:
        print(f"Zone transfer failed: {e}")
        return []

def add_AAAA_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2):
    add_record_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)

def add_MX_record(zone,new_record, new_record_type,new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2 , mx_priority=10):
    new_record_type= "A"
    add_A_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2)
    new_record_type= "MX"
    new_record_value=f"{mx_priority} {new_record}.{zone}."
    add_record_func(zone,"@",new_record_type, new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2)
    return

def add_TXT_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2):
    add_record_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)
    return

def add_NS_record(zone, new_record, new_record_type, new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2):
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
        add_record_func(zone, f"{new_record}", "A", new_record_value, ttl, location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2)
        add_record_func(zone, "@", "NS", f"{new_record}.{zone}.", ttl, location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)
        return

def add_CNAME_record(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master,  location_ip_forwarder_1,location_ip_forwarder_2):
    add_record_func(zone,new_record,new_record_type, new_record_value, ttl,location_ip_master, location_ip_forwarder_1,location_ip_forwarder_2)
    return

def delete_record(zone, new_record, new_record_type, record_value, location_ip_master):
        keyring = dns.tsigkeyring.from_text({constants.key_name: constants.key_secret})
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
            response = dns.query.tcp(update, location_ip_master)
            #run_apply(zone, location_ip_master)

        elif new_record_type == "CNAME":
            fqdn = f"{new_record}.{zone}.".lower()
            update.delete(fqdn, "CNAME")  # Delete entire RRset
        else:
            update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}), keyalgorithm=constants.key_algorithm)
            update.delete(new_record, new_record_type)
            response = dns.query.tcp(update, location_ip_master)
            #run_apply(zone, location_ip_master)

        run_apply(zone, location_ip_master)



def del_record_for_deletation(zone, new_record, new_record_type, record_value, location_ip_master):
    keyring = dns.tsigkeyring.from_text({constants.key_name: constants.key_secret})
    update = dns.update.Update(zone, keyring=keyring, keyalgorithm=constants.key_algorithm)
    record_value = record_value.strip()
    # if record_value.endswith("."):
    #     record_value = record_value[:-1]
    if new_record_type == "NS":

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_master]
        fqdn = f"{new_record}.{zone}".replace("@.", "")
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
        #run_apply(zone, location_ip_master)
        response = dns.query.tcp(update, location_ip_master)
        run_apply(zone, location_ip_master)
    elif new_record_type == "CNAME":
        fqdn = f"{new_record}.{zone}.".lower()
        update.delete(fqdn, "CNAME")  # Delete entire RRset
        response = dns.query.tcp(update, location_ip_master)
        time.sleep(5)
        #run_apply(zone, location_ip_master)
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
        run_apply(zone, location_ip_master)
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
        response = dns.query.tcp(update, location_ip_master)
        #run_apply(zone, location_ip_master)
        return
    else:
        update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}),keyalgorithm=constants.key_algorithm)
        update.delete(new_record, new_record_type)
        response = dns.query.tcp(update, location_ip_master)
        #run_apply(zone, location_ip_master)
    run_apply(zone, location_ip_master)


def update_record(zone,record_name,record_type,  new_record_value,record_value,ttl, location_ip_master,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N=1):
                 # zone, record_name, record_type, second_value, record_value, ttl, location_ip_master, location_ip_forwarder_1, location_ip_forwarder_2
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({constants.key_name: constants.key_secret}), keyalgorithm=constants.key_algorithm)
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
        update_record_with_forwarder_check(zone, record_name, record_type, new_record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1, location_ip_forwarder_2 )


def del_record(zone,record_name,record_type, record_value, ttl, priority, location_ip_master,location_ip_forwarder_1,location_ip_forwarder_2):
    correct_type = checker.check_record_type(record_type)
    zone_exists=checker.zone_existance(zone,location_ip_master )
    checker.record_existance_check_delete(zone ,record_name,record_type,record_value, location_ip_master)
    del_record_for_deletation(zone,record_name,record_type,record_value,location_ip_master)
    for location_ip_forwarder in [location_ip_forwarder_1 , location_ip_forwarder_2]:
        check_forwarder_after_deletation(zone, record_name, record_type, record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2)



def check_forwarder_after_deletation(zone, record_name, record_type, record_value, ttl, location_ip_master,location_ip_forwarder,location_ip_forwarder_1 , location_ip_forwarder_2,check_forwarder_N=1):
    #pass
    if record_type in ["A" , "AAAA" , "PTR","MX", "TXT","NS", "CNAME"]:
        while check_forwarder_N <= 10:
           if check_forwarder_N < 3:
                result = checker.check_forwarder_del(zone, record_name, record_type, record_value, location_ip_master, location_ip_forwarder)
                if result == 3:
                    check_forwarder_N = 10  # success, go on
                    continue
                trigger_reload(zone,location_ip_forwarder)
                check_forwarder_N += 1
           elif check_forwarder_N == 9:
                 raise HTTPException(
                      status_code=403,
                      detail={"error": "فرواردر ها با مستر سینک نشده اند."}
                      )
           elif check_forwarder_N == 10:
                if record_type == "A":
                    ptr_zone = ".".join(record_value.split(".")[:3][::-1]) + ".in-addr.arpa"
                    ptr_name = record_value.split(".")[-1]
                    ptr_value=f"{record_name}.{zone}."
                    del_record_for_deletation(ptr_zone,ptr_name,"PTR", ptr_value, location_ip_master)
                    return
                elif record_type == "AAAA" or record_type == "PTR" or record_type == "MX" or record_type == "TXT" or record_type == "NS" or record_type=="CNAME":
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


def trigger_reload(zone,location_ip_forwarder):

    api2_url = f"http://{location_ip_forwarder}:8000/{zone}/reload/"
    key = b'gEBfVhumi1UeTfMpitUEwsQy5ix_Ot_9OIZBGU6p360='
    cipher_suite = Fernet(key)
    client_ip = '10.60.60.230'
    token = cipher_suite.encrypt(client_ip.encode()).decode()

    headers = {"token": token}
    try:
        r = requests.get(api2_url, headers=headers, timeout=5)
    except requests.RequestException as e:
        raise HTTPException(status_code=403, detail={"error": "Forwarder error after retries"})

def run_apply(zone,location_ip_master):
    api1_url = f"http://{location_ip_master}:8000/{zone}/apply/"
    key = b'gEBfVhumi1UeTfMpitUEwsQy5ix_Ot_9OIZBGU6p360='
    #key = b'g2MoSqxslTG5bZUb-ANegIbzRFq5PQnLxTubqD20nt4='
    cipher_suite = Fernet(key)
    client_ip = '10.60.60.230'
    token = cipher_suite.encrypt(client_ip.encode()).decode()

    headers = {"token": token}
    try:
        r = requests.get(api1_url, headers=headers, timeout=5)
        print("Runing apply command")
    except requests.RequestException as e:
        raise HTTPException(status_code=3, detail={"error": "The master did not update"})
