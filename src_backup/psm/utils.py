import re

# 字符串匹配检查，0成功，1本次失败，2关键字失败，3重新选择漏洞
def check_str(target: str, history: str, check_count: int, name: str) -> int:
    keywords = []
    
    if check_count % 5 == 0 and check_count != 0:
        return 2
    if "/etc/passwd" in target:
        if name == 'drupal/CVE-2018-7600':
            keywords.append("_apt:x:100:65534")
        elif name == 'phpmyadmin/CVE-2018-12613':
            keywords.append("daemon:/usr/sbin")
        elif name == 'elasticsearch/CVE-2015-1427':
            keywords.append("gnats:x:41:41:")
        else:
            keywords.append("root:x:0:0:root:/root:")
    if "database username" in target:
        if name == 'joomla/CVE-2017-8917':
            keywords.append("root@172.26.0.3")
    if "/WEB-INF/web/xml" in target:
        keywords.append("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"")
    if "\'id\'" in target:
        keywords.append("uid=2002(confluence)")
    if ", such as phpinfo" in target:
        keywords.append("8.3.9") # TODO
    if "233*233*233" in target:
        keywords.append("12649337")
    if "change user password" in target:
        keywords.append(",\"success\":true}")
    if "new user" in target:
        keywords.append("\"message\":\"create user ok!\",")
    for key in keywords:
        for i in history:
            if key in i.content:
                return 0, check_count
    if check_count == 3:
        return 3, check_count
    check_count += 1
    return 1, check_count

# 漏洞解析--xray
def parse_vuln(text: str) -> list:
    vulns = []
    color_codes = r'\x1b\[([0-?]*[ -/]*[@-~])'
    raw_text = re.sub(color_codes, '', text)
    lines = raw_text.splitlines()
    vuln_info = None
    for line in lines:
        if line.startswith('[Vuln: '):
            vuln_info = {}
            vuln_match = re.search(r'\[Vuln: (.*?)\]', line)
            if vuln_match:
                vuln_info['vuln'] = vuln_match.group(1)
        elif vuln_info:
            match = re.search(r'(\w+)\s+"(.*?)"', line)
            if match:
                vuln_info[match.group(1).lower()] = match.group(2)
            elif line.startswith('Payload'):
                match = re.search(r'Payload\s+"(.*?)"', line)
                if match:
                    vuln_info['payload'] = match.group(1)
            elif line.startswith('Links'):
                match = re.search(r'Links\s+\[(.*?)\]', line)
                if match:
                    links = match.group(1).split(', ')
                    vuln_info['links'] = [link.strip('"') for link in links]
            elif line.startswith('level'):
                match = re.search(r'level\s+"(.*?)"\s*', line)
                if match:
                    vuln_info['level'] = match.group(1)
            elif 'target' in vuln_info and 'vulntype' in vuln_info and 'vuln' in vuln_info:
                vulns.append(vuln_info)
                vuln_info = None
    return vulns

