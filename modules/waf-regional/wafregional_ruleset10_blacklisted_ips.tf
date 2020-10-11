## 10.
## Generic
## IP Blacklist
## Matches IP addresses that should not be allowed to access content

resource aws_wafregional_rule detect_blacklisted_ips {
  count       = var.disable_blacklisted_ips ? 0 : 1

  name        = "${var.waf_prefix}-generic-detect-blacklisted-ips"
  metric_name = replace("${var.waf_prefix}genericdetectblacklistedips", "/[^0-9A-Za-z]/", "")

  predicate {
    data_id = aws_wafregional_ipset.blacklisted_ips[0].id
    negated = false
    type    = "IPMatch"
  }
}

resource aws_wafregional_ipset blacklisted_ips {
  count       = var.disable_blacklisted_ips ? 0 : 1

  name = "${var.waf_prefix}-generic-match-blacklisted-ips"
  dynamic ip_set_descriptor {
    for_each = var.blacklisted_ips

    content {
      type  = "IPV4"
      value = ip_set_descriptor.value
    }
  }
}

