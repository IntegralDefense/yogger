// rule created from jdavison's brotail whitelist
// avoid alerting on guest wireless traffic
rule whitelist_blackhole_dns_server
{
    meta:
        author = "jdavison,crobinette"
    strings:
	$is_bro = "\"index\":\"bro\"" ascii wide nocase
	$is_pan = "\"index\":\"pan\"" ascii wide nocase
	$from_guest_wireless_1 = /"src_ip":\[?"172.20.\d+.\d+"\]?/
	$from_guest_wireless_2 = /"src_ip":\[?"172.18.\d+.\d+"\]?/
	$from_guest_wireless_3 = /"src_ip":\[?"162.128.69.172"\]?/
	$from_guest_wireless_4 = /"src_ip":\[?"162.128.6.217"\]?/

    condition:
        ($is_bro or $is_pan) and ($from_guest_wireless_1 or $from_guest_wireless_2 or $from_guest_wireless_3 or $from_guest_wireless_4)
}
