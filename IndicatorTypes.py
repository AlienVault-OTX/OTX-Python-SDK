class IndicatorTypes(object):
    """
    IndicatorTypes object define indicators used in OTX.

    :var name string recognized by the OTX platform.
    :var description string verbose description of what the type denotes.
    :var api_support if true, indicator api is supported for this type.
    :var sections indicator List of valid sections for this type (api is split into sections).
    :var slug for building indicator details URLs, similar to name but not always unique (i.e. 'file' for all
              hash types)
    """
    def __init__(self, name, description, api_support=False, sections=None, slug=None):
        self.name = name
        self.description = description
        self.api_support = api_support
        self.sections = sections or []
        self.slug = slug

    def __str__(self):
        return self.name

    def __unicode__(self):
        return unicode(self.name)


IPv4 = IndicatorTypes(
    name="IPv4",
    description="An IPv4 address indicating the online location of a server or other computer.",
    api_support=True,
    sections=["general", "reputation", "geo", "malware", "url_list", "passive_dns"],
    slug="IPv4"
)
IPv6 = IndicatorTypes(
    name="IPv6",
    description="An IPv6 address indicating the online location of a server or other computer.",
    api_support=True,
    sections=["general", "reputation", "geo", "malware", "url_list", "passive_dns"],
    slug="IPv6"
)
DOMAIN = IndicatorTypes(
    name="domain",
    description="A domain name for a website or server. Domains encompass a series of hostnames.",
    api_support=True,
    sections=["general", "geo", "malware", "url_list", "passive_dns"],
    slug="domain"
)
HOSTNAME = IndicatorTypes(
    name="hostname",
    description="The hostname for a server located within a domain.",
    api_support=True,
    sections=["general", "geo", "malware", "url_list", "passive_dns"],
    slug="hostname"
)
EMAIL = IndicatorTypes(
    name="email",
    description="An email associated with suspicious activity."
)
URL = IndicatorTypes(
    name="URL",
    description=" Uniform Resource Location (URL) summarizing the online location of a file or resource.",
    api_support=True,
    sections=["general", "url_list"],
    slug="url"
)
URI = IndicatorTypes(
    name="URI",
    description="Uniform Resource Indicator (URI) describing the explicit path to a file hosted online."
)
FILE_HASH_MD5 = IndicatorTypes(
    name="FileHash-MD5",
    description="A MD5-format hash that summarizes the architecture and content of a file.",
    api_support=True,
    sections=["general", "analysis"],
    slug="file"
)
FILE_HASH_SHA1 = IndicatorTypes(
    name="FileHash-SHA1",
    description="A SHA-format hash that summarizes the architecture and content of a file.",
    api_support=True,
    sections=["general", "analysis"],
    slug="file"
)
FILE_HASH_SHA256 = IndicatorTypes(
    name="FileHash-SHA256",
    description="A SHA-256-format hash that summarizes the architecture and content of a file.",
    api_support=True,
    sections=["general", "analysis"],
    slug="file"
)
FILE_HASH_PEHASH = IndicatorTypes(
    name="FileHash-PEHASH",
    description="A PEPHASH-format hash that summarizes the architecture and content of a file."
)
FILE_HASH_IMPHASH = IndicatorTypes(
    name="FileHash-IMPHASH",
    description="An IMPHASH-format hash that summarizes the architecture and content of a file."
)
CIDR = IndicatorTypes(
    name="CIDR",
    description="Classless Inter-Domain Routing (CIDR) address, which"
                " describes both a server's IP address and the network"
                " architecture (routing path) surrounding that server."
)
FILE_PATH = IndicatorTypes(
    name="FilePath",
    description="A unique location in a file system."
)
MUTEX = IndicatorTypes(
    name="Mutex",
    description="The name of a mutex resource describing the execution architecture of a file."
)
CVE = IndicatorTypes(
    name="CVE",
    description="Common Vulnerability and Exposure (CVE) entry"
                " describing a software vulnerability that can be"
                " exploited to engage in malicious activity.",
    api_support=True,
    sections=["general"],
    slug="cve"
)
YARA = IndicatorTypes(
    name="YARA",
    description="YARA rule",
    api_support=True,
    sections=['general'],
    slug='YARA',
)


# all_types list of supported IOC types for pulse indicators
all_types = [
    IPv4,
    IPv6,
    DOMAIN,
    HOSTNAME,
    EMAIL,
    URL,
    URI,
    FILE_HASH_MD5,
    FILE_HASH_SHA1,
    FILE_HASH_SHA256,
    FILE_HASH_PEHASH,
    FILE_HASH_IMPHASH,
    CIDR,
    FILE_PATH,
    MUTEX,
    CVE
]

# supported_api_types are a subset of all_types for which AlienVault OTX API can offer additional data, such as
# static/dynamic analysis for files, passive dns for hostnames & domains, IP Reputation for IPs, CVE data, etc.
supported_api_types = [
    IPv4,
    IPv6,
    DOMAIN,
    HOSTNAME,
    URL,
    FILE_HASH_MD5,
    FILE_HASH_SHA1,
    FILE_HASH_SHA256,
    CVE
]


def to_name_list(indicator_type_list):
    return [indicator_type.name for indicator_type in indicator_type_list]
