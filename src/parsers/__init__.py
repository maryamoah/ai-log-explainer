from .fortisiem_parser import FortiSIEMParser
from .f5_waf_parser import F5WAFParser
from .trendmicro_parser import TrendMicroParser

def get_parser(name: str):
    name = name.lower()
    if name == "fortisiem":
        return FortiSIEMParser()
    if name == "f5_waf":
        return F5WAFParser()
    if name == "trendmicro":
        return TrendMicroParser()
    raise ValueError(f"Unknown parser: {name}")
