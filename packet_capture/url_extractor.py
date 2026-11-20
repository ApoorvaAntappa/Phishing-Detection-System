import re

def extract_url_from_packet(payload):
    """
    Extract URLs from raw packet payload
    """

    urls = []

    try:
        payload = str(payload)

        # regex for URLs
        url_pattern = r"(https?://[^\s\"']+)"

        found = re.findall(url_pattern, payload)

        for url in found:
            urls.append(url)

    except:
        pass

    return urls