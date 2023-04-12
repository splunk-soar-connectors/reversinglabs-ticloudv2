def file_reputation(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = {}

            malware_presence = result.get_data()[0].get("rl", {}).get("malware_presence")
            data["malware_presence"] = malware_presence
            data["classification_color"] = color_code_classification(malware_presence.get("status").upper())

            context['data'] = data

    return 'views/reversinglabs_file_reputation.html'


def av_scanners(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = {}

            sample = result.get_data()[0].get("rl", {}).get("sample")
            data["sample"] = sample

            context['data'] = data

    return 'views/reversinglabs_av_scanners.html'


def file_analysis(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = {}

            sample = result.get_data()[0].get("rl", {}).get("sample")
            data["sample"] = sample

            context['data'] = data

    return 'views/reversinglabs_file_analysis.html'


def uri_statistics(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = {}

            uri_state = result.get_data()[0].get("rl", {}).get("uri_state")
            data["uri_state"] = uri_state

            uri_type = uri_state.get("uri_type")
            uri = uri_state.get(uri_type)
            data["uri"] = uri
            data["uri_type"] = uri_type

            context['data'] = data

    return 'views/reversinglabs_uri_statistics.html'


def url_reputation(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = {}

            report_base = result.get_data()[0].get("rl", {})
            data["report_base"] = report_base

            classification = report_base.get("classification", "UNAVAILABLE").upper()
            data["classification"] = classification
            data["classification_color"] = color_code_classification(classification)

            context['data'] = data

    return 'views/reversinglabs_url_reputation.html'


def analyze_url(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = {}

            report_base = result.get_data()[0].get("rl", {})
            data["report_base"] = report_base

            context['data'] = data

    return 'views/reversinglabs_analyze_url.html'


def submit_for_dynamic_analysis(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = {}

            report_base = result.get_data()[0].get("rl", {})
            data["report_base"] = report_base

            context['data'] = data

    return 'views/reversinglabs_submit_for_dynamic.html'


def dynamic_analysis_results(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = {}

            report_base = result.get_data()[0].get("rl", {})
            data["report_base"] = report_base
            data["classification_color"] = color_code_classification(report_base.get("report").get("classification", "UNKNOWN"))

            context['data'] = data
            context['param'] = result.get_param()

    return 'views/reversinglabs_dynamic_analysis_results.html'


def advanced_search(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['results_found'] = f"Results found: {str(len(result.get_data()))}"
            data = result.get_data()
            for x in data:
                x["classification_color"] = color_code_classification(x.get("classification").upper())

            context["data"] = data
            context['param'] = result.get_param()

    return 'views/reversinglabs_advanced_search.html'


def functional_similarity(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['results_found'] = f"Results found: {str(len(result.get_data()))}"
            data = result.get_data()
            for x in data:
                x["classification_color"] = color_code_classification(x.get("classification").upper())

            context["data"] = data
            context['param'] = result.get_param()

    return 'views/reversinglabs_functional_similarity.html'


def imphash_similarity(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['results_found'] = f"Results found: {str(len(result.get_data()))}"
            data = result.get_data()
            # for x in data:
            #     x["classification_color"] = color_code_classification(x.get("classification").upper())

            context["data"] = data
            context['param'] = result.get_param()

    return 'views/reversinglabs_imphash_similarity.html'


def uri_index(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['results_found'] = f"Results found: {str(len(result.get_data()))}"
            context['data'] = result.get_data()
            context['param'] = result.get_param()

    return 'views/reversinglabs_uri_index.html'


def color_code_classification(classification):
    color = ""
    classification = classification.upper()
    if classification == 'MALICIOUS':
        color = "red"
    elif classification == 'SUSPICIOUS':
        color = "orange"
    elif classification == 'KNOWN' or classification == "CLEAN":
        color = "green"

    return color
