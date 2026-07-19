import time
import httpx
from fastapi import HTTPException
import dns.query  # to use axfr
import dns.zone  # Access zone's data
import dns.update  # add record
import dns.tsigkeyring  # authenticate
import dns.resolver  # chech zone
import dns.rdatatype
import dns.reversename
from cryptography.fernet import Fernet
from bind_manager import checker
import ipaddress
import logging
from config.logging_config import setup_logging
from config.settings import settings
import dns.message
import dns.flags
import dns.name
import dns.rcode
from run import freeze_and_thaw_zone

setup_logging()
logger = logging.getLogger(__name__)
keyring = dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET})


def add_record(zone, new_record, new_record_type, new_record_value, ttl, priority, location_ip_master,
               forwarders, operation_id):
    checker.check_record_type(new_record_type)  ###Checking for correct type
    checker.zone_existance(zone, location_ip_master)  ###Check if the zone exists in nameserver
    record_exist = checker.record_existance(zone, new_record, new_record_type, location_ip_master)
    if record_exist:
        raise HTTPException(
            status_code=409,  # conflict
            detail={"error": "This record already exists with another address and cannot be added again. "}
        )
    return add_record_by_type(zone, new_record, new_record_type, new_record_value, ttl,priority, location_ip_master,
                              forwarders, operation_id)


def add_record_by_type(zone, new_record, new_record_type, new_record_value, ttl,priority, location_ip_master,
                       forwarders, operation_id):
    func_map = {
        "A": add_A_record,
        "AAAA": add_AAAA_record,
        "TXT": add_TXT_record,
        "MX": add_MX_record,
        "NS": add_NS_record,
        "CNAME": add_CNAME_record,
        "PTR": add_PTR_record
    }

    func = func_map.get(new_record_type)
    return func(zone, new_record, new_record_type, new_record_value, ttl,priority, location_ip_master, forwarders, operation_id)


def add_A_record(zone, new_record, new_record_type, new_record_value, ttl,priority, location_ip_master, forwarders, operation_id):
    """" Add A record and PTR record """
    try:
        ipaddress.IPv4Address(new_record_value)
    except ValueError as err:
        raise HTTPException(
            status_code=400,  # BAD_REQUEST
            detail={"error": "The provided value is not a valid IPv4 address.", "value": new_record_value}
        ) from err
    logger.info(f"Adding A record: {new_record} -> {new_record_value} in zone {zone}")
    add_record_func(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master,
                    forwarders, operation_id)
    if settings.AUTO_CREATE_PTR_FOR_A_RECORD:
        try:
            ptr_zone = ".".join(new_record_value.split(".")[:3][::-1]) + ".in-addr.arpa"
            ptr_name = new_record_value.split(".")[-1]
            ptr_value = f"{new_record}.{zone}."
            logger.info(f"Adding PTR record: {ptr_name} -> {ptr_value} in zone {ptr_zone}")
            add_record_func(ptr_zone, ptr_name, "PTR", ptr_value, ttl, location_ip_master,
                            forwarders, operation_id)
            logger.info(f"PTR record {ptr_name} successfully added to zone {ptr_zone}")
        except Exception as e:
            logger.error(f"PTR creation failed: {e}")
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "A record was created successfully but PTR record creation failed.",
                    "a_record_created": True,
                    "ptr_record_created": False,
                    "ptr_error": str(e)
                }
            )



def add_PTR_record(zone, new_record, new_record_type, new_record_value, ttl,priority, location_ip_master,
                   forwarders, operation_id):
    logger.info(f"Attempting to add PTR record {new_record_value} in zone {zone}")
    try:
        PTR_LAST_OCTET_LIMIT = 255
        if not 0 < int(new_record) <= PTR_LAST_OCTET_LIMIT:
            logger.error(f"PTR record {new_record} exceeds limit {PTR_LAST_OCTET_LIMIT}")
            raise HTTPException(
                status_code=400,  # Bad request
                detail={"error": "Invalid PTR record value. Last octet must be less than 255.",
                        "ptr_record": new_record}
            )
        ptr_records = get_all_ptr_records(zone, location_ip_master)
        targets_only = {target for _, target in ptr_records}  # use set for O(1) lookup
        if new_record_value in targets_only:
            logger.error(f"PTR record value {new_record_value} already exists in zone {zone}")
            raise HTTPException(
                status_code=409,
                detail={"error": "The record value already exists.", "ptr_record": new_record_value}
            )
        logger.info(f"Adding PTR record {new_record_value} -> {new_record}.{zone}")
        add_record_func(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master,
                        forwarders, operation_id)
        logger.info(f"PTR record {new_record_value} successfully added to zone {zone}")

    except ValueError:
        raise HTTPException(
            status_code=400,  # BAD_REQUEST
            detail={"error": "The value is not proper for PTR record"}
        )


def get_all_ptr_records(zone_name, location_ip_master):
    """
    Return all PTR records as generator (full_name, target)
    """
    try:
        zone = dns.zone.from_xfr(
            dns.query.xfr(
                where=location_ip_master,
                zone=zone_name,
                keyring=dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET}),
                keyname=dns.name.from_text(settings.KEY_NAME),
                keyalgorithm=settings.KEY_ALGORITHM
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


def add_AAAA_record(zone, new_record, new_record_type, new_record_value, ttl,priority, location_ip_master,
                    forwarders, operation_id):
    logger.info(f"Attempting to add AAAA record {new_record_value} in zone {zone}")
    try:
        ipaddress.IPv6Address(new_record_value)
    except ValueError as e:
        logger.error(f"Invalid IPv6 address: {e}")
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid IPv6 address for AAAA record"}
        ) from e
    add_record_func(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master,forwarders, operation_id)
    logger.info(f"AAAA record added {new_record_value} in zone {zone}")



def add_TXT_record(zone, new_record, new_record_type, new_record_value, ttl,priority, location_ip_master,
                   forwarders, operation_id):
    logger.info(f"Attempting to add TXT record {new_record_value} in zone {zone}")
    add_record_func(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master,
                    forwarders, operation_id)
    logger.info(f"TXT record {new_record_value} successfully added to zone {zone}")


def add_MX_record(zone, new_record, new_record_type, new_record_value, ttl,priority, location_ip_master, forwarders, operation_id):
    new_record_value = f"{priority} {new_record_value}."
    add_record_func(zone, "@", "MX", new_record_value, ttl, location_ip_master, forwarders, operation_id)
    logger.info(f"MX record {new_record_value} successfully added to zone {zone}")


def add_NS_record(zone, new_record, new_record_type, new_record_value, ttl,priority, location_ip_master,forwarders, operation_id):
    add_record_func(zone, f"{new_record}", "A", new_record_value, ttl, location_ip_master, forwarders, operation_id)
    logger.info(f"A record {new_record_value} successfully added to zone {zone}")
    add_record_func(zone, "@", "NS", f"{new_record}.{zone}.", ttl, location_ip_master, forwarders, operation_id)
    logger.info(f"NS record {new_record_value} successfully added to zone {zone}")


def add_CNAME_record(zone, new_record, new_record_type, new_record_value, ttl,priority, location_ip_master,
                     forwarders, operation_id):
    logger.info(f"Attempting to add CNAME record {new_record_value} in zone {zone}")
    add_record_func(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master,
                    forwarders, operation_id)
    logger.info(f"CNAME record {new_record_value} successfully added to zone {zone}")


def add_record_func(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master,
                    forwarders, operation_id, current_retry_attempt=1):
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET}),
                               keyalgorithm=settings.KEY_ALGORITHM)
    update.add(new_record, ttl, new_record_type, new_record_value)
    response = dns.query.tcp(update, location_ip_master)
    if response.rcode() != dns.rcode.NOERROR:
       error_text = dns.rcode.to_text(response.rcode())
       raise HTTPException(
           status_code=403,
           detail={"error": f"DNS Update failed with rcode: {error_text}", "zone": zone}
       )
    freeze_and_thaw_zone(zone)
    for location_ip_forwarder in forwarders:
        verify_forwarder_after_record_add(zone, new_record, new_record_type, new_record_value, ttl, location_ip_master,
                                          location_ip_forwarder,
                                          operation_id)


def verify_forwarder_after_record_add(
        zone,
        new_record,
        new_record_type,
        new_record_value,
        ttl,
        location_ip_master,
        location_ip_forwarder,
        operation_id,
        current_retry_attempt=1

):

    key_name = f"{new_record_type}-{new_record}"

    values_for_multiple_records[key_name] = {
        "data": (
            zone,
            new_record,
            new_record_type,
            new_record_value,
            ttl,
            location_ip_master,
            location_ip_forwarder,
            current_retry_attempt,
        ),
        "operation_id": operation_id,
    }

    logger.debug(f"MAX_RETRY={settings.MAX_RETRY}, current_retry_attempt={current_retry_attempt}")

    while current_retry_attempt <= settings.MAX_RETRY:
        logger.info(f"Forwarder check attempt {current_retry_attempt}/{settings.MAX_RETRY} for {key_name}")

        if current_retry_attempt < settings.MAX_RETRY - 1:
            result = checker.check_forwarder_for_adding(zone, new_record, new_record_type, new_record_value,
                                                        location_ip_master, location_ip_forwarder)

            if result == settings.MAX_RETRY:
                logger.info(f" Forwarder {location_ip_forwarder} synced successfully for {key_name}")
                current_retry_attempt = settings.MAX_RETRY
                continue

            wait_for_forwarder_reload(location_ip_forwarder, zone, operation_id)
            current_retry_attempt += 1

        elif current_retry_attempt == settings.MAX_RETRY - 1:
            logger.error(f"Forwarder {location_ip_forwarder} did not sync for {key_name}. Rolling back...")

            for stored_key, info in list(values_for_multiple_records.items()):
                if info["operation_id"] == operation_id:
                    data = info["data"]
                    delete_record_logic(
                        data[0],  # zone
                        data[1],  # new_record
                        data[2],  # new_record_type
                        data[3],  # new_record_value
                        data[5],  # location_ip_master
                        data[6],  # location_ip_forwarder
                    )
                    del values_for_multiple_records[stored_key]
                    logger.warning(f"Rolled back {stored_key} (op_id={operation_id})")

            raise HTTPException(
                status_code=502,
                detail={
                    "error": f"ِForwarder {location_ip_forwarder} is not synced with the master. The operation was rolled back."},
            )

        elif current_retry_attempt == settings.MAX_RETRY:
            logger.info(f"🟢 Forwarder verification loop completed for {key_name}")
            return None


values_for_multiple_records = {}


def verify_forwarder_after_record_update(
        zone,
        new_record,
        new_record_type,
        new_record_value,
        ttl,
        location_ip_master,
        location_ip_forwarder,
        operation_id,
        current_retry_attempt=1,

):
    key_name = f"{new_record_type}-{new_record}"

    values_for_multiple_records[key_name] = {
        "data": (
            zone,
            new_record,
            new_record_type,
            new_record_value,
            ttl,
            location_ip_master,
            location_ip_forwarder,
            current_retry_attempt,
        ),
        "operation_id": operation_id,
    }

    while current_retry_attempt <= settings.MAX_RETRY:
        logger.info(f"Forwarder check attempt {current_retry_attempt}/{settings.MAX_RETRY} for {key_name}")

        if current_retry_attempt < settings.MAX_RETRY - 1:
            result = checker.check_forwarder_for_adding(zone, new_record, new_record_type, new_record_value,
                                                        location_ip_master, location_ip_forwarder)

            if result == settings.MAX_RETRY:
                logger.info(f" Forwarder {location_ip_forwarder} synced successfully for {key_name}")
                current_retry_attempt = settings.MAX_RETRY
                continue

            wait_for_forwarder_reload(location_ip_forwarder, zone, operation_id)
            current_retry_attempt += 1

        elif current_retry_attempt == settings.MAX_RETRY - 1:
            logger.error(f"Forwarder {location_ip_forwarder} did not sync for {key_name}.")

            raise HTTPException(
                status_code=502,
                detail={"error": f"ِForwarder {location_ip_forwarder} is not synced with the master."},
            )

        elif current_retry_attempt == settings.MAX_RETRY:
            logger.info(f"🟢 Forwarder verification loop completed for {key_name}")
            return None


def delete_record_logic(zone, record_name, record_type, record_value, location_ip_master, location_ip_forwarder):
    checker.check_record_type(record_type)
    checker.zone_existance(zone, location_ip_master)
    checker.record_existance_check_delete(zone, record_name, record_type, record_value, location_ip_master)
    delete_record(zone, record_name, record_type, record_value, location_ip_master)


def delete_record(zone, new_record, new_record_type, record_value, location_ip_master):
    update = dns.update.Update(zone, keyring=keyring, keyalgorithm=settings.KEY_ALGORITHM)
    record_value = record_value.strip()
    if record_value.endswith("."):
        record_value = record_value[:-1]
    if new_record_type == "MX":
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
                match = NS
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
        #dns.query.tcp(update, location_ip_master)
    elif new_record_type == "CNAME":
        fqdn = f"{new_record}.{zone}.".lower()
        update.delete(fqdn, "CNAME")  # Delete entire RRset
    else:
        update.delete(new_record, new_record_type)
    response = dns.query.tcp(update, location_ip_master)
    if response.rcode() != dns.rcode.NOERROR:
        error_text = dns.rcode.to_text(response.rcode())
        raise HTTPException(
            status_code=403,
            detail={"error": f"DNS Update failed with rcode: {error_text}", "zone": zone}
        )
    freeze_and_thaw_zone(zone)


def del_record_for_deletation(zone, new_record, new_record_type, record_value, location_ip_master, operation_id):
    update = dns.update.Update(zone, keyring=keyring, keyalgorithm=settings.KEY_ALGORITHM)
    if new_record_type == "NS":
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_master]
        # fqdn = f"{new_record}.{zone}".replace("@.", "")
        answers = resolver.resolve(zone, "NS")
        current_NS = [r.to_text() for r in answers]
        match = None
        if record_value in current_NS:
            for NS in current_NS:
                if record_value == NS:
                    update.delete(new_record, "NS", NS)
                    # response = dns.query.tcp(update, location_ip_master)
                    break
        else:
            raise HTTPException(
                status_code=403,
                detail={"error": "This record value does not exist", "record_value": record_value}
            )
    elif new_record_type == "CNAME":
        fqdn = f"{new_record}.{zone}.".lower()
        update.delete(fqdn, "CNAME")  # Delete entire RRset
    elif new_record_type == "PTR":
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_master]
        fqdn = f"{new_record}.{zone}"
        answers = resolver.resolve(fqdn, "PTR")
        current_ptr = [r.to_text() for r in answers]
        match = None
        if record_value in current_ptr:
            update.delete(new_record, new_record_type, record_value)
        else:
            raise HTTPException(
                status_code=403,
                detail={"error": "This record value does not exist", "record_value": record_value}
            )

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
                detail={"error": "This record value does not exist.(MX)", }
            )
        update.delete(new_record, "MX", match)
    else:
        update.delete(new_record, new_record_type)
    response = dns.query.tcp(update, location_ip_master)
    if response.rcode() != dns.rcode.NOERROR:
        error_text = dns.rcode.to_text(response.rcode())
        raise HTTPException(
            status_code=502,
            detail={"error": f"DNS Update failed with rcode: {error_text}", "zone": zone}
        )
    else:
        freeze_and_thaw_zone(zone)

def send_dns_update(update, location_ip_master, zone):
    response = dns.query.tcp(update, location_ip_master)

    if response.rcode() != dns.rcode.NOERROR:
        error_text = dns.rcode.to_text(response.rcode())
        raise HTTPException(
            status_code=502,
            detail={
                "error": f"DNS Update failed with rcode: {error_text}",
                "zone": zone
            }
        )

    return response



def update_record(zone, record_name, record_type, new_record_value, record_value, ttl, location_ip_master,
                  forwarders, operation_id):
    update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET}),
                               keyalgorithm=settings.KEY_ALGORITHM)
    if record_type == "MX":
        query = dns.message.make_query(record_value, dns.rdatatype.from_text("A"))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        # resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_master, timeout=3)
        except Exception as e:
            logger.warning(e)
            response = None

        if response and response.answer:
            resolved_ips = [str(item) for answer in response.answer for item in answer.items]
            if not resolved_ips:
                raise HTTPException(
                    status_code=404,
                    detail={"error": "No A record found for MX target."}
                )
            update.delete(record_value, "A")
            #dns.query.tcp(update, location_ip_master)
            send_dns_update(update, location_ip_master, zone)
            freeze_and_thaw_zone(zone)
            update.add(new_record_value, ttl, "A", resolved_ips[0])
            #dns.query.tcp(update, location_ip_master)
            send_dns_update(update, location_ip_master, zone)
            freeze_and_thaw_zone(zone)
            # update.replace(record_name, ttl, record_type, new_record_value)

            del_record_for_deletation(zone, record_name, record_type, record_value, location_ip_master, operation_id)
            mx_priority = "10"
            new_record_value = f"{mx_priority} {new_record_value}"
            add_record_func(zone, "@", record_type, new_record_value, ttl, location_ip_master, forwarders, operation_id)

    elif record_type == "NS":
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_master]
        # fqdn = f"{new_record}.{zone}".replace("@.", "")
        answers = resolver.resolve(zone, "NS")
        current_NS = [r.to_text() for r in answers]
        match = None
        if record_value in current_NS:
            for NS in current_NS:
                if record_value == NS:
                    update.delete(record_name, "NS", NS)
                    # response = dns.query.tcp(update, location_ip_master)
                    break
        else:
            raise HTTPException(
                status_code=403,
                detail={"error": f"This record value does not exist ", "record_value": record_value}
            )

        query = dns.message.make_query(record_value, dns.rdatatype.from_text("A"))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_master, timeout=3)
        except Exception as e:
            logger.warning(e)
            response = None

        if response and response.answer:
            resolved_ips = [str(item) for answer in response.answer for item in answer.items]
        if not resolved_ips:
            raise HTTPException(
                status_code=404,
                detail={"error": f"No record found for {record_value}"}
            )
        #     del_record_for_deletation(zone, record_name, record_type, record_value, location_ip_master,operation_id)
        #     update.delete(record_value, "A")
        #     dns.query.tcp(update, location_ip_master)
        #     freeze_and_thaw_zone(zone)
        update.add(new_record_value, ttl, "A", resolved_ips[0])
        #dns.query.tcp(update, location_ip_master)
        send_dns_update(update, location_ip_master, zone)
        freeze_and_thaw_zone(zone)
        add_record_func(zone, "@", record_type, new_record_value, ttl, location_ip_master, forwarders, operation_id)
    elif record_type == "PTR":
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_master]
        fqdn = f"{record_name}.{zone}"
        answers = resolver.resolve(fqdn, "PTR")
        current_ptr = [r.to_text() for r in answers]
        match = None
        if record_value in current_ptr:
            update = dns.update.Update(zone,
                                       keyring=dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET}),
                                       keyalgorithm=settings.KEY_ALGORITHM)
            update.delete(record_name, record_type, record_value)
            #dns.query.tcp(update, location_ip_master)
            send_dns_update(update, location_ip_master, zone)
            freeze_and_thaw_zone(zone)

            update = dns.update.Update(zone,
                                       keyring=dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET}),
                                       keyalgorithm=settings.KEY_ALGORITHM)
            update.add(record_name, ttl, record_type, new_record_value)
            #dns.query.tcp(update, location_ip_master)
        else:
            raise HTTPException(
                status_code=403,
                detail={"error": f"This record value does not exist ", "record_value": record_value}
            )

    else:
        update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET}),
                                   keyalgorithm=settings.KEY_ALGORITHM)
        update.replace(record_name, ttl, record_type, new_record_value)
        #dns.query.tcp(update, location_ip_master)
    send_dns_update(update, location_ip_master, zone)
    freeze_and_thaw_zone(zone)
    for location_ip_forwarder in forwarders:
        verify_forwarder_after_record_update(zone, record_name, record_type, new_record_value, ttl, location_ip_master,
                                              location_ip_forwarder,
                                             operation_id)


def del_record(zone, record_name, record_type, record_value, ttl, priority, location_ip_master, forwarders, operation_id):
    checker.check_record_type(record_type)
    checker.zone_existance(zone, location_ip_master)
    checker.record_existance_check_delete(zone, record_name, record_type, record_value, location_ip_master)
    del_record_for_deletation(zone, record_name, record_type, record_value, location_ip_master, operation_id)
    for location_ip_forwarder in forwarders:
        check_forwarder_after_deletation(zone, record_name, record_type, record_value, ttl, location_ip_master,
                                         location_ip_forwarder,
                                         operation_id)


def check_forwarder_after_deletation(zone, record_name, record_type, record_value, ttl, location_ip_master,
                                     location_ip_forwarder,operation_id, current_retry_attempt=1):
    while current_retry_attempt <= settings.MAX_RETRY:
        logger.info(f"Forwarder check attempt {current_retry_attempt}/{settings.MAX_RETRY}")
        if current_retry_attempt < settings.MAX_RETRY - 1:

            result = checker.check_forwarder_del(zone, record_name, record_type, record_value, location_ip_master,
                                                 location_ip_forwarder)
            if result == settings.MAX_RETRY:
                logger.info(f" Forwarder {location_ip_forwarder} synced successfully.")
                current_retry_attempt = settings.MAX_RETRY
                continue

            wait_for_forwarder_reload(location_ip_forwarder, zone, operation_id)
            current_retry_attempt += 1

        elif current_retry_attempt == settings.MAX_RETRY - 1:
            logger.error(f"Forwarder {location_ip_forwarder} did not sync.")
            raise HTTPException(
                status_code=502,
                detail={"error": f"ِForwarder {location_ip_forwarder} is not synced with the master."},
            )

        elif current_retry_attempt == settings.MAX_RETRY:
            logger.info(f"🟢 Forwarder verification loop completed.")
            return None


def update_record_progress(zone, record_name, record_type, record_value, second_value, ttl, priority, location_ip_master,
                            forwarders, operation_id):
    checker.check_record_type(record_type)
    checker.zone_existance(zone, location_ip_master)
    checker.record_existance_check_delete(zone, record_name, record_type, record_value, location_ip_master)
    update_record(zone, record_name, record_type, second_value, record_value, ttl, location_ip_master,
                  forwarders, operation_id)



def wait_for_forwarder_reload(forwarder_ip: str, zone: str, operation_id):
    cipher_suite = Fernet(settings.fernet_key.encode())
    token = cipher_suite.encrypt(settings.client_ip.encode()).decode()
    headers = {"token": token}

    api_reload_url = f"http://{forwarder_ip}:8000/{zone}/reload/"
    status_url = f"http://{forwarder_ip}:8000/{zone}/reload/status/"

    with httpx.Client() as client:
        # Trigger reload
        try:
            r = client.post(api_reload_url, headers=headers, timeout=5)
            r.raise_for_status()
        except httpx.RequestError as e:
            logger.error(f"Forwarder reload failed for zone {zone} - {e}")
            logger.error(f"Failed to contact forwarder {forwarder_ip}: {e}")
            for stored_key, info in list(values_for_multiple_records.items()):
                if info["operation_id"] == operation_id:
                    data = info["data"]
                    delete_record_logic(
                        data[0],  # zone
                        data[1],  # new_record
                        data[2],  # new_record_type
                        data[3],  # new_record_value
                        data[5],  # location_ip_master
                        data[6],  # location_ip_forwarder
                    )

                    del values_for_multiple_records[stored_key]
                    logger.warning(f"Rolled back {stored_key} (op_id={operation_id}), Record deleted")
            raise HTTPException(status_code=503, detail=f"Forwarder not reachable: {forwarder_ip} ")
        except httpx.HTTPStatusError as e:
            logger.error(f"Forwarder reload failed for zone {zone} - {e}")
            logger.error(f"Forwarder reload request failed: {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)

        logger.info(f"Reload triggered for zone {zone} on forwarder {forwarder_ip}")

        # Exponential backoff up to 60 seconds
        interval = 1
        while interval <= 60:
            try:
                r_status = client.get(status_url, headers=headers, timeout=5)
                r_status.raise_for_status()
                status = r_status.json().get("status")
            except Exception as e:
                logger.warning(f"Error checking reload status for {forwarder_ip}: {e}")
                status = None

            logger.info(f"The status of reloading forwarder is: {status}")

            if status == "done":
                logger.info(f"Forwarder {forwarder_ip} finished reloading zone {zone}")
                return True
            elif status == "error":
                raise HTTPException(status_code=500, detail=f"Forwarder failed reloading zone {zone}")

            logger.debug(f"Waiting {interval} seconds before next check...")
            time.sleep(interval)

            # Exponential growth but capped at 60
            interval = min(interval * 2, 60)

        # If loop ends, that means we reached the 60s cap
        raise HTTPException(status_code=504, detail="Timeout waiting for forwarder reload")
