import logging
from fastapi import HTTPException
from config import settings
import dns.query
import dns.zone
import dns.tsigkeyring
import dns.resolver
import dns.rdatatype
import ipaddress
import dns.message
import dns.flags
import dns.name
from dns.rdtypes.ANY.MX import MX
from config.settings import settings

logger = logging.getLogger(__name__)


def check_record_type(record_type):
    if record_type not in ["A", "AAAA", "NS", "MX", "CNAME", "TXT", "PTR"]:
        raise HTTPException(
            status_code=404,
            detail={"error": "The record type is not correct.", "type": record_type}
        )


def zone_existance(zone, location_ip_master):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [location_ip_master]
    try:
        resolver.resolve(zone, "SOA", lifetime=3)
        return True
    except Exception as e:
        raise HTTPException(
            status_code=404,  # NOT_FOUND
            detail={"error": "The zone does not exist or is not accessible.", "zone": zone}
        )


def record_existance(zone, new_record, new_record_type, location_ip_master):
    keyring = dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET})
    if new_record_type == "PTR":
        return False

    elif new_record_type == "NS":
        new_ns_record = f"{new_record}"
        try:
            zone_data = dns.zone.from_xfr(
                dns.query.xfr(
                    location_ip_master,
                    zone,
                    keyring=keyring,
                    keyname=dns.name.from_text(settings.KEY_NAME),
                    keyalgorithm=settings.KEY_ALGORITHM,
                )
            )
        except Exception as e:
            logger.error(f"AXFR failed: {e}")
            return False

        record_value = new_ns_record.rstrip(".").lower() + "."

        for name, node in zone_data.nodes.items():

            # NS records are always on zone apex (@)
            if str(name) != "@":
                continue

            for rdataset in node.rdatasets:

                # check type
                if rdataset.rdtype != dns.rdatatype.NS:
                    continue

                for rdata in rdataset:

                    # check value
                    if str(rdata.target) == new_ns_record:
                        logger.info(
                            f"NS record already exists: {zone}. -> {record_value}.{zone}"
                        )
                        return True

        return False

    else:
        """Retrieve zone data via AXFR transfer."""
        zone_data = dns.zone.from_xfr(
            dns.query.xfr(
                location_ip_master,
                zone,
                keyring=keyring,
                keyname=dns.name.from_text(settings.KEY_NAME),
                keyalgorithm=settings.KEY_ALGORITHM,
            )
        )

        records = []
        for name, node in zone_data.nodes.items():
            for rdataset in node.rdatasets:
                record_type = dns.rdatatype.to_text(rdataset.rdtype)
                records.append(f"{name}.{zone} {record_type}")
                if str(name) == new_record and record_type == new_record_type:
                    return True
        return False


def record_existance_check_delete(zone, new_record, new_record_type, record_value, location_ip_master):
    """Retrieve zone data via AXFR transfer."""
    keyring = dns.tsigkeyring.from_text({settings.KEY_NAME: settings.KEY_SECRET})
    zone_data = dns.zone.from_xfr(
        dns.query.xfr(
            location_ip_master,
            zone,
            keyring=keyring,
            keyname=dns.name.from_text(settings.KEY_NAME),
            keyalgorithm=settings.KEY_ALGORITHM,
        )
    )

    if new_record_type == "MX":
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_master]

        try:
            answers = resolver.resolve(zone, "MX")

        except Exception as e:
            logger.warning(f"Error checking MX record: {e}")
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "Unable to verify MX record.",
                    "reason": str(e)
                }
            )

        for rdata in answers:
            value_in_server = str(rdata.exchange).rstrip('.')
            if str(value_in_server.lower()) == str(record_value.rstrip('.').lower()):
                return True

        raise HTTPException(
            status_code=404,
            detail={
                "error": "Your record deletion request failed. "
                         "Reason: The record does not exist."
            }
        )

    elif new_record_type in ["PTR"]:
        fqdn_name = f"{new_record}.{zone}."
        record_value = record_value.rstrip(".") + "."
        ptr_value = []
        for name, node in zone_data.nodes.items():
            node_fqdn = f"{name}.{zone}."
            ptr_value.append(node_fqdn)
        if fqdn_name not in ptr_value:
            raise HTTPException(
                status_code=404,
                detail={"error": "Your record deletion request failed."
                                 "Reason: The record does not exist."}
            )


    else:
        records = []
        for name, node in zone_data.nodes.items():
            for rdataset in node.rdatasets:
                if new_record_type == "NS":
                    name = f"{zone}."

                record_type = dns.rdatatype.to_text(rdataset.rdtype)
                records.append(f"{name}.{zone} {record_type}")
                if str(name) == new_record and record_type == new_record_type:
                    check_the_value(zone, new_record, new_record_type, record_value, location_ip_master)
                    return True
        raise HTTPException(
            status_code=404,
            detail={"error": "Your record deletion request failed."
                             "Reason: The record does not exist."}
        )


def check_forwarder_for_adding(zone, new_record, new_record_type, new_record_value, location_ip_master,
                               location_ip_forwarder):
    if new_record_type in ["A", "AAAA", "TXT"]:
        fqdn = f"{new_record}.{zone}"
        query = dns.message.make_query(fqdn, dns.rdatatype.from_text(new_record_type))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        resolved_ips = []
        try:
            response = dns.query.udp(query, location_ip_forwarder, timeout=3)
        except Exception as e:
            logger.warning(e)
            response = None

        if response and response.answer:
            resolved_ips = [str(item) for answer in response.answer for item in answer.items]
        if new_record_type == "A":
            if new_record_value in resolved_ips:
                current_retry_attempt = settings.MAX_RETRY
                return current_retry_attempt
        elif new_record_type == "AAAA":
            try:
                expected_ip = ipaddress.IPv6Address(new_record_value)
                normalized_resolved = [ipaddress.IPv6Address(ip) for ip in resolved_ips]
                if expected_ip in normalized_resolved:
                    current_retry_attempt = settings.MAX_RETRY
                    return current_retry_attempt
            except ValueError as e:
                logger.warning(f"Invalid IPv6 address provided: {e}")
        elif new_record_type == "TXT":
            expected_txt = new_record_value.strip('"')
            found_txt_records = [item.strip('"') for item in resolved_ips]
            if expected_txt in found_txt_records:
                current_retry_attempt = settings.MAX_RETRY
                return current_retry_attempt
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
        if new_record_value in resolved_ips:
            current_retry_attempt = settings.MAX_RETRY
            return current_retry_attempt
    if new_record_type in ["MX"]:
        dns_server = location_ip_forwarder
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        #mx_value = []
        try:
            answers = resolver.resolve(zone, "MX")
            new_record_value = new_record_value.split()[1].rstrip('.')
            for rdata in answers:
                rdata: MX
                mx_record_in_server = str(rdata.exchange).rstrip('.')
                #mx_value.append(new_record_value)
                if mx_record_in_server.lower() == new_record_value.lower():
                    current_retry_attempt = settings.MAX_RETRY
                    return current_retry_attempt
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
                current_retry_attempt = settings.MAX_RETRY
                return current_retry_attempt
            else:
                return False
        except Exception as e:
            logger.warning(f"Error checking NS: {e}")
        return False

    if new_record_type == "CNAME":
        fqdn = f"{new_record}.{zone}."  ###########.rstrip('.')
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
            current_retry_attempt = settings.MAX_RETRY
            return current_retry_attempt
        else:
            if resolved_target is None:
                return False


def check_forwarder_del(zone, new_record, record_type, record_value, location_ip_master, location_ip_forwarder):
    if record_type in ["A", "AAAA", "TXT"]:
        fqdn = f"{new_record}.{zone}"
        query = dns.message.make_query(fqdn, dns.rdatatype.from_text(record_type))
        query.flags |= dns.flags.RD  # Recursion Desired flag
        try:
            response = dns.query.udp(query, location_ip_forwarder, timeout=3)
        except Exception as e:
            logger.error(f"DNS query failed: {e} . forwarder is not  available")
            raise HTTPException(
                status_code=403,
                detail={"error": "Forwarder is not answering."}
            )
        resolved_ips = [str(item) for answer in response.answer for item in answer.items]
        if record_type == "A":
            if record_value not in resolved_ips:
                current_retry_attempt = settings.MAX_RETRY
                return current_retry_attempt
            else:
                logger.info(f"Record {fqdn} is still exist. Found: {resolved_ips}")
        if record_type == "AAAA":
            try:
                expected_ip = ipaddress.IPv6Address(record_value.strip())
                resolved_ipv6_set = {
                ipaddress.IPv6Address(ip.strip()) for ip in resolved_ips
                }

                if expected_ip not in resolved_ipv6_set:
                    current_retry_attempt = settings.MAX_RETRY
                    return current_retry_attempt
                else:
                    logger.error(f"Record {fqdn} is still exist. Found: {resolved_ips}")

            except ValueError as e:
                logger.error(f"Invalid IPv6 address provided: {e}")
                raise HTTPException(
                    status_code=400,
                    detail={"error": f"Invalid IPv6 address format: '{record_value}'"}
                )

        if record_type == "TXT":
            expected_txt = record_value.strip('"')
            found_txt_records = [item.strip('"') for item in resolved_ips]
            if expected_txt not in found_txt_records:
                current_retry_attempt = settings.MAX_RETRY
                return current_retry_attempt

    if record_type == "PTR":
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [location_ip_forwarder]
            fqdn = f"{new_record}.{zone}"
            answers = resolver.resolve(fqdn, "PTR")

            current_ptr = [r.to_text() for r in answers]
            if record_value not in current_ptr:
                #current_retry_attempt = settings.MAX_RETRY
                return settings.MAX_RETRY
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return settings.MAX_RETRY
        except Exception as e:
            logger.warning(f"DNS query failed: {e}")
            #response = None
            raise HTTPException(
                status_code=403,
                detail={"error": "Forwarder is not answering."}
            ) from e

    if record_type in ["MX"]:
        dns_server = location_ip_forwarder
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        mx_value = []
        try:
            answers = resolver.resolve(zone, "MX")
            for rdata in answers:
                mx_record_in_server = str(rdata.exchange)  ##.rstrip('.')
                new_record_value = record_value  ##.split()[1].rstrip('.')
                mx_value.append(mx_record_in_server)
            if record_value not in mx_value:
                current_retry_attempt = settings.MAX_RETRY
                return current_retry_attempt

            return False
        except Exception as e:
            logger.error(f"Error checking MX: {e}")
            return False

    if record_type == "NS":
        dns_server = location_ip_forwarder
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        try:
            answers = resolver.resolve(zone, "NS")
            ns_list = [str(rdata.target).rstrip('.') for rdata in answers]
            expected_ns = record_value.rstrip('.')
            if expected_ns not in ns_list:
                current_retry_attempt = settings.MAX_RETRY
                return current_retry_attempt
            else:
                return False
        except Exception as e:
            logger.error(f"Error checking NS: {e}")
        # return False

    if record_type == "CNAME":
        fqdn = f"{new_record}.{zone}".rstrip('.')
        query = dns.message.make_query(fqdn, dns.rdatatype.from_text(record_type))
        query.flags |= dns.flags.RD
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [location_ip_forwarder]
        try:
            response = dns.query.udp(query, location_ip_forwarder, timeout=3)
            try:
                answers = resolver.resolve(fqdn, "CNAME", raise_on_no_answer=False)
                # Handle case: the domain exists, but has no CNAME
                if not answers.rrset:
                    resolved_target = None
                    current_retry_attempt = settings.MAX_RETRY
                    return current_retry_attempt
                # Got a CNAME
                resolved_target = str(answers[0].target).rstrip('.')
            except dns.resolver.NXDOMAIN:
                logger.info(f"{fqdn} does not exist in DNS.")
                resolved_target = None
                current_retry_attempt = settings.MAX_RETRY
                return current_retry_attempt
            except Exception:
                resolved_target = None
                current_retry_attempt = settings.MAX_RETRY
                return current_retry_attempt
            # Compare resolved target with expected CNAME
            expected_cname = record_value.rstrip('.')
            if resolved_target and resolved_target.lower() != expected_cname.lower():
                current_retry_attempt = settings.MAX_RETRY
                return current_retry_attempt
            else:
                if resolved_target is None:
                    return False
        except Exception as e:
            logger.warning(f"DNS query failed: {e} . forwarder does not available")
            response = None
            raise HTTPException(
                status_code=403,
                detail={"error": "Forwarder is not answering."}
            )


def check_the_value(zone, record_name, record_type, record_value, location_ip_master):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [location_ip_master]
    if record_type == "MX":
        # Extract only the hostname part (after priority) and strip trailing dot
        record_value = record_value.split()[1].rstrip('.')

    try:
        if record_type != "NS":
            fqdn = f"{record_name}.{zone}".lower()
            answers = resolver.resolve(fqdn, record_type)
            resolved_ips = [str(answer) for answer in answers]
            #resolved_ips = str(resolved_ips)
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
                    detail={"error": "Record value does not match"}
                )
    except HTTPException:
        raise

    except Exception as e:
        logger.error(f"DNS lookup failed: {e}")
        raise HTTPException(
            status_code=502,
            detail={"error": "Unable to verify record value"}
        ) from e

# def check_command_type(command):
#     if not command == "apply":
#         logger.warning(f"Command {command} is not supported!, Wrong request")
#         raise HTTPException(
#             status_code=406,
#             detail={"messege": "The command is not correct"}
#         )
#     logger.info(f"Command {command} is supported!")



