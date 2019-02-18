// rule created from jdavison's brotail whitelist
// avoid alerting on AD servers refreshing cache againse blackhole server
rule whitelist_blackhole_dns_server
{
    meta:
        author = "jdavison,crobinette"
    strings:
	$is_bro = "\"index\":\"bro\"" ascii wide nocase
	$is_dns = "\"type\":\"dns\"" ascii wide nocase
	$to_blackhole_server = "\"dst_ip\":[\"149.55.45.222\"]" ascii wide nocase
	$from_ad_1 = "\"src_ip\":[\"149.55.45.222\"]" ascii wide nocase
	$from_ad_2 = "\"src_ip\":[\"162.128.44.74\"]" ascii wide nocase
	$from_ad_3 = "\"src_ip\":[\"162.128.98.78\"]" ascii wide nocase

    condition:
        $is_bro and $is_dns and $to_blackhole_server and ($from_ad_1 or $from_ad_2 or $from_ad_3)
}
