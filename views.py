def file_reputation(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = construct_file_reputation(result.get_data()[0])

    return 'views/reversinglabs_view.html'


def av_scanners(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = construct_avscanners(result.get_data()[0])

    return 'views/reversinglabs_view.html'


def file_analysis(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = construct_file_analysis(result.get_data()[0])

    return 'views/reversinglabs_view.html'


def uri_statistics(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = construct_uri_statistics(result.get_data()[0])

    return 'views/reversinglabs_view.html'


def advanced_search(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = f"Results found: {str(len(result.get_data()))}"

    return 'views/reversinglabs_view.html'


def functional_similarity(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = f"Results found: {str(len(result.get_data()))}"

    return 'views/reversinglabs_view.html'


def uri_index(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = f"Results found: {str(len(result.get_data()))}"

    return 'views/reversinglabs_view.html'


def url_reputation(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = construct_url_reputation(result.get_data()[0])

    return 'views/reversinglabs_view.html'


def analyze_url(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = construct_uanalyze_url(result.get_data()[0])

    return 'views/reversinglabs_view.html'


def submit_for_dynamic_analysis(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = construct_submit_for_dynamic_analysis(result.get_data()[0])

    return 'views/reversinglabs_view.html'


def construct_file_reputation(result):
    malware_presence = result.get("rl", {}).get("malware_presence")
    if not malware_presence:
        return "There is no malware_presence object in the response JSON."

    classification = malware_presence.get("status")
    reason = malware_presence.get("reason")
    threat_name = malware_presence.get("threat_name")

    md5 = malware_presence.get("md5")
    sha1 = malware_presence.get("sha1")
    sha256 = malware_presence.get("sha256")

    data = f"""<b>ReversingLabs File Reputation for hash :</b> {sha1} \n
    <b>Classification:</b> {color_code_classification(classification)}
    <b>Classification reason:</b> {reason}
    <b>First seen:</b> {malware_presence.get("first_seen")}
    <b>Last seen:</b> {malware_presence.get("last_seen")}
    <b>AV scanner hits / total number of scanners:</b> {malware_presence.get("scanner_match")} / {malware_presence.get(
        "scanner_count")}
    <b>AV scanner hit percentage:</b> {malware_presence.get("scanner_percent")}%
    <b>MD5 hash:</b> {md5}
    <b>SHA-1 hash:</b> {sha1}
    <b>SHA-256 hash:</b> {sha256}"""
    if classification.upper() in ("MALICIOUS", "SUSPICIOUS"):
        data = f"""{data}
        <b>Threat name:</b> {threat_name}
        <b>Threat level:</b> {malware_presence.get("threat_level")}
        """
    elif classification.upper() == "KNOWN":
        data = f"""{data}
        <b>Trust factor:</b> {malware_presence.get("trust_factor")}
        """
    else:
        data = f"""ReversingLabs File Reputation for hash {sha1}\n Classification: {classification}
        No references were found for this hash.
        """
    return data


def construct_avscanners(result):
    sample = result.get("rl", {}).get("sample")
    if not sample:
        return "There is no sample object in the response JSON."

    md5 = sample.get("md5")
    sha1 = sample.get("sha1")
    sha256 = sample.get("sha256")

    data = f"""<b>ReversingLabs AV Scan results for hash:</b> {sha1}\n
    <b>First scanned on:</b> {sample.get("first_scanned_on")}
    <b>First seen on:</b> {sample.get("first_seen_on")}
    <b>Last scanned on:</b> {sample.get("last_scanned_on")}
    <b>Last seen on:</b> {sample.get("last_seen_on")}
    <b>Sample size:</b> {sample.get("sample_size")} bytes
    <b>Sample type:</b> {sample.get("sample_type")}
    <b>MD5 hash:</b> {md5}
    <b>SHA-1 hash:</b> {sha1}
    <b>SHA-256 hash:</b> {sha256}
    <b>SHA-512 hash:</b> {sample.get("sha512")}
    <b>SHA-384 hash:</b> {sample.get("sha384")}
    <b>RIPEMD-160 hash:</b> {sample.get("ripemd160")}
    """
    if sample.get("xref"):
        if len(sample.get("xref")) > 0:
            data += "\n <b>Scanner results:</b> \n"
            for xref in sample.get("xref")[0].get("results"):
                data += f"""\n <b>{xref.get("scanner")}</b>: {xref.get("result")}"""

    return data


def construct_file_analysis(result):
    sample = result.get("rl", {}).get("sample")
    if not sample:
        return "There is no sample object in the response JSON."

    sha1 = sample.get("sha1")

    entries = sample.get("analysis").get("entries")
    if len(entries) == 0:
        return "The entries list is empty"

    tc_report = entries[0].get("tc_report")

    file_type = tc_report.get("info").get("file").get("file_type")
    file_subtype = tc_report.get("info").get("file").get("file_subtype")

    rldata_xref = sample.get("xref")

    data = f"""<b>ReversingLabs File Analysis results for hash:</b> {sha1}\n
    <b>File type:</b> {file_type}
    <b>File subtype:</b> {file_subtype}
    <b>Sample type:</b> {rldata_xref.get("sample_type")}
    <b>Sample size:</b> {sample.get("sample_size")} bytes \n
    <b>Extended description:</b> {tc_report.get("story")} \n
    <b>First seen:</b> {rldata_xref.get("first_seen")}
    <b>Last seen:</b> {rldata_xref.get("last_seen")}
    <b>MD5 hash:</b> {sample.get("md5")}
    <b>SHA-1 hash:</b> {sample.get("sha1")}
    <b>SHA-256 hash:</b> {sample.get("sha256")}
    <b>SHA-384 hash:</b> {sample.get("sha384")}
    <b>SHA-512 hash:</b> {sample.get("sha512")}
    <b>SSDEEP hash:</b> {sample.get("ssdeep")}
    <b>RIPEMD-160 hash:</b> {sample.get("ripemd160")}
    """

    return data


def construct_uri_statistics(result):
    uri_state = result.get("rl", {}).get("uri_state")
    if not uri_state:
        return "There is no uri_state object in the response JSON."

    counters = uri_state.get("counters")
    uri_type = uri_state.get("uri_type")
    uri = uri_state.get(uri_type)
    uri_types = {
        "domain": f"<b>Domain:</b> {uri}",
        "url": f"<b>URL:</b> {uri}",
        "ipv4": f"<b>IPv4:</b> {uri}",
        "email": f"<b>Email:</b> {uri}"
    }

    data = f"""<b>ReversingLabs URI Statistics results for URI:</b> {uri}\n
    <b>Sample counters:</b>
    <b><font color="green">KNOWN:</font></b> {counters.get("known")}
    <b><font color="red">MALICIOUS:</font></b> {counters.get("malicious")}
    <b><font color="orange">SUSPICIOUS:</font></b> {counters.get("suspicious")}
    <b>SHA-1 hash:</b> {uri_state.get("sha1")}
    <b>URI type:</b> {uri_type}
    {uri_types.get(uri_type)}"""

    return data


def construct_url_reputation(result):
    report_base = result.get("rl")

    if not report_base:
        return "There is no rl object in the response JSON."

    classification = report_base.get("classification", "UNAVAILABLE").upper()
    data = f"""<b>ReversingLabs URL Threat Intelligence report for URL:</b> {report_base.get(
        "requested_url")} \n
    <b>Classification:</b> {color_code_classification(classification)}\n"""

    analysis = report_base.get("analysis")
    if analysis:
        statistics = analysis.get("statistics")

        last_analysis = analysis.get("last_analysis")

        data += f"""<b>First analysis:</b> {analysis.get("first_analysis")}
        <b>Analysis count:</b> {analysis.get("analysis_count")} \n
        <b>Last analysis:</b>
        <b>Analysis ID:</b> {last_analysis.get("analysis_id")}
        <b>Analysis time:</b> {last_analysis.get("analysis_time")}
        <b>Final URL:</b> {last_analysis.get("final_url")}
        <b>Availability status:</b> {last_analysis.get("availability_status")}
        <b>Domain:</b> {last_analysis.get("domain")}
        <b>Serving IP Address:</b> {last_analysis.get("serving_ip_address")}\n
        <b>Statistics:</b>
        <b><font color="green">KNOWN:</font></b> {statistics.get("known")}
        <b><font color="orange">SUSPICIOUS:</font></b> {statistics.get("suspicious")}
        <b><font color="red">MALICIOUS:</font></b> {statistics.get("malicious")}
        <b>UNKNOWN:</b> {statistics.get("unknown")}
        <b>TOTAL:</b> {statistics.get("total")}"""

    return data


def construct_uanalyze_url(result):
    report_base = result.get("rl", {})

    data = f"""<b>ReversingLabs Analyze URL response for URL:</b> {report_base.get("requested_url")}\n
    <b>Status:</b> {report_base.get("status")}
    <b>Analysis ID:</b> {report_base.get("analysis_id")}"""

    return data


def construct_submit_for_dynamic_analysis(result):
    report_base = result.get("rl", {})

    data = f"""<b>ReversingLabs ReversingLabs Submit Sample {report_base.get("requested_hash")} for Dynamic Analysis:</b>\n
    <b>Status:</b> {report_base.get("status")}
    <b>Analysis ID:</b> {report_base.get("analysis_id")}"""

    return data


def color_code_classification(classification):
    classification = classification.upper()
    if classification == 'MALICIOUS':
        classification = f'<font color="red">{classification}</font>'
    elif classification == 'SUSPICIOUS':
        classification = f'<font color="orange">{classification}</font>'
    elif classification == 'KNOWN':
        classification = f'<font color="green">{classification}</font>'

    return classification
