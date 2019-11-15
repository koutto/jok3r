#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match

# Match wafw00f 1.0.0
WAFW00F_REGEXP = r'The site http.* is behind {}'

products_match['http']['web-application-firewall'] = {
    'aeSecure/aeSecure': {
        'wafw00f': [
            WAFW00F_REGEXP.format('aeSecure \(aeSecure\)'),
        ],
    },
    'Phion/Ergon/Airlock': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Airlock \(Phion/Ergon\)'),
        ],
    },
    'Alert Logic/Alert Logic': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Alert Logic \(Alert Logic\)'),
        ],
    },
    'Alibaba Cloud Computing/AliYunDun': {
        'wafw00f': [
            WAFW00F_REGEXP.format('AliYunDun \(Alibaba Cloud Computing\)'),
        ],
    },
    'Anquanbao/Anquanbao': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Anquanbao \(Anquanbao\)'),
        ],
    },
    'AnYu Technologies/AnYu': {
        'wafw00f': [
            WAFW00F_REGEXP.format('AnYu \(AnYu Technologies\)'),
        ],
    },
    'Approach/Approach': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Approach \(Approach\)'),
        ],
    },
    'Armor/Armor Defense': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Armor Defense \(Armor\)'),
        ],
    },
    'Microsoft/ASP.NET Generic Protection': {
        'wafw00f': [
            WAFW00F_REGEXP.format('ASP.NET Generic Protection \(Microsoft\)'),
        ],
    },
    'Czar Securities/Astra Web Protection': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Astra Web Protection \(Czar Securities\)'),
        ],
    },
    'Amazon/AWS Elastic Load Balancer': {
        'wafw00f': [
            WAFW00F_REGEXP.format('AWS Elastic Load Balancer \(Amazon\)'),
        ],
    },
    'Baidu Cloud Computing/Yunjiasu': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Yunjiasu \(Baidu Cloud Computing\)'),
        ],
    },
    'Ethic Ninja/Barikode': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Barikode \(Ethic Ninja\)'),
        ],
    },
    'Barracuda Networks/Barracuda Application Firewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Barracuda Application Firewall \(Barracuda Networks\)'),
        ],
    },
    'Faydata Technologies Inc./Bekchy': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Bekchy \(Faydata Technologies Inc\.\)'),
        ],
    },
    'BinarySec/BinarySec': {
        'wafw00f': [
            WAFW00F_REGEXP.format('BinarySec \(BinarySec\)'),
        ],
    },
    'BitNinja/BitNinja': {
        'wafw00f': [
            WAFW00F_REGEXP.format('BitNinja \(BitNinja\)'),
        ],
    },
    'BlockDoS/BlockDoS': {
        'wafw00f': [
            WAFW00F_REGEXP.format('BlockDoS \(BlockDoS\)'),
        ],
    },
    'Bluedon IST/Bluedon': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Bluedon \(Bluedon IST\)'),
        ],
    },
    'Varnish/CacheWall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('CacheWall \(Varnish\)'),
        ],
    },
    'CdnNs/WdidcNet/CdnNS Application Gateway': {
        'wafw00f': [
            WAFW00F_REGEXP.format('CdnNS Application Gateway \(CdnNs/WdidcNet\)'),
        ],
    },
    'Cerber Tech/WP Cerber Security': {
        'wafw00f': [
            WAFW00F_REGEXP.format('WP Cerber Security \(Cerber Tech\)'),
        ],
    },
    'ChinaCache/ChinaCache CDN Load Balancer': {
        'wafw00f': [
            WAFW00F_REGEXP.format('ChinaCache CDN Load Balancer \(ChinaCache\)'),
        ],
    },
    'Yunaq/Chuang Yu Shield': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Chuang Yu Shield \(Yunaq\)'),
        ],
    },
    'Cisco/ACE XML Gateway': {
        'wafw00f': [
            WAFW00F_REGEXP.format('ACE XML Gateway \(Cisco\)'),
        ],
    },
    'Penta Security/Cloudbric': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Cloudbric \(Penta Security\)'),
        ],
    },
    'Cloudflare Inc./Cloudflare': {
        'wappalyzer': 'CloudFlare',
        'wafw00f': [
            WAFW00F_REGEXP.format('Cloudflare \(Cloudflare Inc\.\)'),
        ],
    },
    'Amazon/Cloudfront': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Cloudfront \(Amazon\)'),
        ],
    },
    'Comodo CyberSecurity/Comodo cWatch': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Comodo cWatch \(Comodo CyberSecurity\)'),
        ],
    },
    'Jean-Denis Brun/CrawlProtect': {
        'wafw00f': [
            WAFW00F_REGEXP.format('CrawlProtect \(Jean-Denis Brun\)'),
        ],
    },
    'Rohde & Schwarz CyberSecurity/DenyALL': {
        'wafw00f': [
            WAFW00F_REGEXP.format('DenyALL \(Rohde & Schwarz CyberSecurity\)'),
        ],
    },
    'Distil Networks/Distil': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Distil \(Distil Networks\)'),
        ],
    },
    'DOSarrest Internet Security/DOSarrest': {
        'wafw00f': [
            WAFW00F_REGEXP.format('DOSarrest \(DOSarrest Internet Security\)'),
        ],
    },
    'Applicure Technologies/DotDefender': {
        'wafw00f': [
            WAFW00F_REGEXP.format('DotDefender \(Applicure Technologies\)'),
        ],
    },
    'DynamicWeb/DynamicWeb Injection Check': {
        'wafw00f': [
            WAFW00F_REGEXP.format('DynamicWeb Injection Check \(DynamicWeb\)'),
        ],
    },
    'Verizon Digital Media/Edgecast': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Edgecast \(Verizon Digital Media\)'),
        ],
    },
    'EllisLab/Expression Engine': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Expression Engine \(EllisLab\)'),
        ],
    },
    'F5 Networks/BIG-IP Access Policy Manager': {
        'wafw00f': [
            WAFW00F_REGEXP.format('BIG-IP Access Policy Manager \(F5 Networks\)'),
        ],
    },
    'F5 Networks/BIG-IP Application Security Manager': {
        'wafw00f': [
            WAFW00F_REGEXP.format('BIG-IP Application Security Manager \(F5 Networks\)'),
        ],
    },
    'F5 Networks/BIG-IP Local Traffic Manager': {
        'wafw00f': [
            WAFW00F_REGEXP.format('BIG-IP Local Traffic Manager \(F5 Networks\)'),
        ],
    },
    'F5 Networks/FirePass': {
        'wafw00f': [
            WAFW00F_REGEXP.format('FirePass \(F5 Networks\)'),
        ],
    },
    'F5 Networks/Trafficshield': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Trafficshield \(F5 Networks\)'),
        ],
    },
    'Fortinet/FortiWeb': {
        'wafw00f': [
            WAFW00F_REGEXP.format('FortiWeb \(Fortinet\)'),
        ],
    },
    'GoDaddy/GoDaddy Website Protection': {
        'wafw00f': [
            WAFW00F_REGEXP.format('GoDaddy Website Protection \(GoDaddy\)'),
        ],
    },
    'Grey Wizard/Greywizard': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Greywizard \(Grey Wizard\)'),
        ],
    },
    'Art of Defense/HyperGuard': {
        'wafw00f': [
            WAFW00F_REGEXP.format('HyperGuard \(Art of Defense\)'),
        ],
    },
    'IBM/DataPower': {
        'wafw00f': [
            WAFW00F_REGEXP.format('DataPower \(IBM\)'),
        ],
    },
    'CloudLinux/Imunify360': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Imunify360 \(CloudLinux\)'),
        ],
    },
    'Imperva Inc./Incapsula': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Incapsula \(Imperva Inc\.\)'),
        ],
    },
    'Instart Logic/Instart DX': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Instart DX \(Instart Logic\)'),
        ],
    },
    'Microsoft/ISA Server': {
        'wafw00f': [
            WAFW00F_REGEXP.format('ISA Server \(Microsoft\)'),
        ],
    },
    'Janusec/Janusec Application Gateway': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Janusec Application Gateway \(Janusec\)'),
        ],
    },
    'Jiasule/Jiasule': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Jiasule \(Jiasule\)'),
        ],
    },
    'KnownSec/KS-WAF': {
        'wafw00f': [
            WAFW00F_REGEXP.format('KS-WAF \(KnownSec\)'),
        ],
    },
    'Akamai/Kona Site Defender': {
        'wappalyzer': 'AkamaiGHost extrainfo: Akamai\'s HTTP',
        'wafw00f': [
            WAFW00F_REGEXP.format('Kona Site Defender \(Akamai\)'),
        ],
    },
    'LiteSpeed Technologies/LiteSpeed Firewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('LiteSpeed Firewall \(LiteSpeed Technologies\)'),
        ],
    },
    'Inactiv/Malcare': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Malcare \(Inactiv\)'),
        ],
    },
    'Mission Control/Mission Control Application Shield': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Mission Control Application Shield \(Mission Control\)'),
        ],
    },
    'SpiderLabs/ModSecurity': {
        'wafw00f': [
            WAFW00F_REGEXP.format('ModSecurity \(SpiderLabs\)'),
        ],
    },
    'NBS Systems/NAXSI': {
        'wafw00f': [
            WAFW00F_REGEXP.format('NAXSI \(NBS Systems\)'),
        ],
    },
    'PentestIt/Nemesida': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Nemesida \(PentestIt\)'),
        ],
    },
    'Barracuda Networks/NetContinuum': {
        'wafw00f': [
            WAFW00F_REGEXP.format('NetContinuum \(Barracuda Networks\)'),
        ],
    },
    'Citrix Systems/NetScaler AppFirewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('NetScaler AppFirewall \(Citrix Systems\)'),
        ],
    },
    'AdNovum/NevisProxy': {
        'wafw00f': [
            WAFW00F_REGEXP.format('NevisProxy \(AdNovum\)'),
        ],
    },
    'NewDefend/Newdefend': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Newdefend \(NewDefend\)'),
        ],
    },
    'NexusGuard/NexusGuard Firewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('NexusGuard Firewall \(NexusGuard\)'),
        ],
    },
    'NinTechNet/NinjaFirewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('NinjaFirewall \(NinTechNet\)'),
        ],
    },
    'NSFocus Global Inc./NSFocus': {
        'wafw00f': [
            WAFW00F_REGEXP.format('NSFocus \(NSFocus Global Inc.\)'),
        ],
    },
    'BlackBaud/OnMessage Shield': {
        'wafw00f': [
            WAFW00F_REGEXP.format('OnMessage Shield \(BlackBaud\)'),
        ],
    },
    'Palo Alto Networks/Palo Alto Next Gen Firewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Palo Alto Next Gen Firewall \(Palo Alto Networks\)'),
        ],
    },
    'PerimeterX/PerimeterX': {
        'wafw00f': [
            WAFW00F_REGEXP.format('PerimeterX \(PerimeterX\)'),
        ],
    },
    'PowerCDN/PowerCDN': {
        'wafw00f': [
            WAFW00F_REGEXP.format('PowerCDN \(PowerCDN\)'),
        ],
    },
    'ArmorLogic/Profense': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Profense \(ArmorLogic\)'),
        ],
    },
    'Radware/AppWall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('AppWall \(Radware\)'),
        ],
    },
    'Reblaze/Reblaze': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Reblaze \(Reblaze\)'),
        ],
    },
    'RSJoomla!/RSFirewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('RSFirewall \(RSJoomla\!\)'),
        ],
    },
    'Microsoft/ASP.NET RequestValidationMode': {
        'wafw00f': [
            WAFW00F_REGEXP.format('ASP.NET RequestValidationMode \(Microsoft\)'),
        ],
    },
    'Sabre/Sabre Firewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Sabre Firewall \(Sabre\)'),
        ],
    },
    'Safe3/Safe3 Web Firewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Safe3 Web Firewall \(Safe3\)'),
        ],
    },
    'SafeDog/Safedog': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Safedog \(SafeDog\)'),
        ],
    },
    'Chaitin Tech./Safeline': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Safeline \(Chaitin Tech.\)'),
        ],
    },
    'SecuPress/SecuPress WordPress Security': {
        'wafw00f': [
            WAFW00F_REGEXP.format('SecuPress WordPress Security \(SecuPress\)'),
        ],
    },
    'United Security Providers/Secure Entry': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Secure Entry \(United Security Providers\)'),
        ],
    },
    'BeyondTrust/eEye SecureIIS': {
        'wafw00f': [
            WAFW00F_REGEXP.format('eEye SecureIIS \(BeyondTrust\)'),
        ],
    },
    'Imperva Inc./SecureSphere': {
        'wafw00f': [
            WAFW00F_REGEXP.format('SecureSphere \(Imperva Inc\.\)'),
        ],
    },
    'Neusoft/SEnginx': {
        'wafw00f': [
            WAFW00F_REGEXP.format('SEnginx \(Neusoft\)'),
        ],
    },
    'One Dollar Plugin/Shield Security': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Shield Security \(One Dollar Plugin\)'),
        ],
    },
    'SiteGround/SiteGround': {
        'wafw00f': [
            WAFW00F_REGEXP.format('SiteGround \(SiteGround\)'),
        ],
    },
    'Sakura Inc./SiteGuard': {
        'wafw00f': [
            WAFW00F_REGEXP.format('SiteGuard \(Sakura Inc\.\)'),
        ],
    },
    'TrueShield/Sitelock': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Sitelock \(TrueShield\)'),
        ],
    },
    'Dell/SonicWall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('SonicWall \(Dell\)'),
        ],
    },
    'Sophos/UTM Web Protection': {
        'wafw00f': [
            WAFW00F_REGEXP.format('UTM Web Protection \(Sophos\)'),
        ],
    },
    'Squarespace/Squarespace': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Squarespace \(Squarespace\)'),
        ],
    },
    'StackPath/StackPath': {
        'wafw00f': [
            WAFW00F_REGEXP.format('StackPath \(StackPath\)'),
        ],
    },
    'Sucuri Inc./Sucuri CloudProxy': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Sucuri CloudProxy \(Sucuri Inc\.\)'),
        ],
    },
    'Tencent Technologies/Tencent Cloud Firewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Tencent Cloud Firewall \(Tencent Technologies\)'),
        ],
    },
    'Citrix Systems/Teros': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Teros \(Citrix Systems\)'),
        ],
    },
    'TransIP/TransIP Web Firewall': {
        'wafw00f': [
            WAFW00F_REGEXP.format('TransIP Web Firewall \(TransIP\)'),
        ],
    },
    'iFinity/DotNetNuke/URLMaster SecurityCheck': {
        'wafw00f': [
            WAFW00F_REGEXP.format('URLMaster SecurityCheck \(iFinity/DotNetNuke\)'),
        ],
    },
    'Microsoft/URLScan': {
        'wafw00f': [
            WAFW00F_REGEXP.format('URLScan \(Microsoft\)'),
        ],
    },
    'OWASP/Varnish': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Varnish \(OWASP\)'),
        ],
    },
    'VirusDie LLC/VirusDie': {
        'wafw00f': [
            WAFW00F_REGEXP.format('VirusDie \(VirusDie LLC\)'),
        ],
    },
    'Wallarm Inc./Wallarm': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Wallarm \(Wallarm Inc\.\)'),
        ],
    },
    'WatchGuard Technologies/WatchGuard': {
        'wafw00f': [
            WAFW00F_REGEXP.format('WatchGuard \(WatchGuard Technologies\)'),
        ],
    },
    'WebARX Security Solutions/WebARX': {
        'wafw00f': [
            WAFW00F_REGEXP.format('WebARX \(WebARX Security Solutions\)'),
        ],
    },
    'AQTRONIX/WebKnight': {
        'wafw00f': [
            WAFW00F_REGEXP.format('WebKnight \(AQTRONIX\)'),
        ],
    },
    'IBM/WebSEAL': {
        'wafw00f': [
            WAFW00F_REGEXP.format('WebSEAL \(IBM\)'),
        ],
    },
    'WebTotem/WebTotem': {
        'wafw00f': [
            WAFW00F_REGEXP.format('WebTotem \(WebTotem\)'),
        ],
    },
    'Feedjit/Wordfence': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Wordfence \(Feedjit\)'),
        ],
    },
    'WTS/WTS-WAF': {
        'wafw00f': [
            WAFW00F_REGEXP.format('WTS-WAF \(WTS\)'),
        ],
    },
    '360 Technologies/360WangZhanBao': {
        'wafw00f': [
            WAFW00F_REGEXP.format('360WangZhanBao \(360 Technologies\)'),
        ],
    },
    'XLabs/XLabs Security WAF': {
        'wafw00f': [
            WAFW00F_REGEXP.format('XLabs Security WAF \(XLabs\)'),
        ],
    },
    'Yundun/Yundun': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Yundun \(Yundun\)'),
        ],
    },
    'Yunsuo/Yunsuo': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Yunsuo \(Yunsuo\)'),
        ],
    },
    'Zenedge/Zenedge': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Zenedge \(Zenedge\)'),
        ],
    },
    'Accenture/ZScaler': {
        'wafw00f': [
            WAFW00F_REGEXP.format('ZScaler \(Accenture\)'),
        ],
    },
    'Accenture/ZScaler': {
        'wafw00f': [
            WAFW00F_REGEXP.format('ZScaler \(Accenture\)'),
        ],
    },
    'West263 Content Delivery Network': {
        'wafw00f': [
            WAFW00F_REGEXP.format('West263 Content Delivery Network'),
        ],
    },
    'pkSecurity Intrusion Detection System': {
        'wafw00f': [
            WAFW00F_REGEXP.format('pkSecurity Intrusion Detection System'),
        ],
    },   
    'Xuanwudun': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Xuanwudun'),
        ],
    },   
    'Open-Resty Lua Nginx WAF': {
        'wafw00f': [
            WAFW00F_REGEXP.format('Open-Resty Lua Nginx WAF'),
        ],
    },
}