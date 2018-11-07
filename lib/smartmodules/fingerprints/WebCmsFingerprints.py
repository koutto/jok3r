# -*- coding: utf-8 -*-
###
### SmartModules > Fingerprints > WebCmsFingerprint
###

# >>> text
# '\x1b[3J\x1b[H\x1b[2J\x1b[3J\x1b[H\x1b[2J\x1b[1m\x1b[32m\n\x1b[32m_\x1b[97m___ _  _ \x1b[32m__\x1b[97m__ ____ \x1b[32m____\x1b[97m _  \x1b[32m_\x1b[97m\n|    |\x1b[32m\\/\x1b[97m| \x1b[32m[\x1b[97m__  \x1b[32m|\x1b[97m___ |\x1b[32m___\x1b[97m |\x1b[32m_\x1b[97m/  \x1b[36mby \x1b[91m@r3dhax0r\x1b[97m\n\x1b[32m|\x1b[97m_\x1b[32m__\x1b[97m |  | ___\x1b[32m|\x1b[97m |\x1b[32m___\x1b[97m \x1b[32m|\x1b[97m___ \x1b[32m|\x1b[97m \\\x1b[32m_\x1b[97m \x1b[93mVersion 1.1.0\x1b[32m ForumZ\n\n\x1b[107m\x1b[30m\x1b[1m\x1b[1m\n [+]  CMS Detection And Deep Scan  [+] \x1b[0m\n\x1b[0m\n\n\x1b[1m\x1b[36m[i] \x1b[0mScanning Site: http://www.drupal.com\n[+] User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0\n[+] Collecting Headers and Page Source for Analysis\n[+] Detection Started\n[+] Using headers to detect CMS (Stage 1 of 4)\n[+] Skipping stage 2 of 4: No Generator meta tag found\n\x1b[1m\x1b[32m[*] \x1b[0mCMS Detected, CMS ID: \x1b[1m\x1b[32mdru\x1b[0m, Detection method: \x1b[1m\x1b[36mheader\x1b[0m\n[+] Getting CMS info from database\n\x1b[1m\x1b[32m[*] \x1b[0mStarting version detection\n[+] Detecting version using generator meta tag [Method 1 of 2]\n\x1b[1m\x1b[32m[*] \x1b[0mDrupal version \x1b[1m8\x1b[0m detected\n\x1b[1m\x1b[32m\n\x1b[32m_\x1b[97m___ _  _ \x1b[32m__\x1b[97m__ ____ \x1b[32m____\x1b[97m _  \x1b[32m_\x1b[97m\n|    |\x1b[32m\\/\x1b[97m| \x1b[32m[\x1b[97m__  \x1b[32m|\x1b[97m___ |\x1b[32m___\x1b[97m |\x1b[32m_\x1b[97m/  \x1b[36mby \x1b[91m@r3dhax0r\x1b[97m\n\x1b[32m|\x1b[97m_\x1b[32m__\x1b[97m |  | ___\x1b[32m|\x1b[97m |\x1b[32m___\x1b[97m \x1b[32m|\x1b[97m___ \x1b[32m|\x1b[97m \\\x1b[32m_\x1b[97m \x1b[93mVersion 1.1.0\x1b[32m ForumZ\n\n\x1b[107m\x1b[30m\x1b[1m\x1b[1m\n [+]  CMS Scan Results  [+] \x1b[0m\n\x1b[0m\n\n ┏━Target: \x1b[1m\x1b[91mwww.drupal.com\x1b[0m\n ┃\n ┠── CMS: \x1b[1m\x1b[32mDrupal\x1b[0m\n ┃    │\n ┃    ├── Version: \x1b[1m\x1b[32m8\x1b[0m\n ┃    ╰── URL: \x1b[32mhttps://drupal.org\x1b[0m\n ┃\n ┠── Result: \x1b[1m\x1b[32m/root/jok3r/toolbox/http/cmseek/Result/www.drupal.com/cms.json\x1b[0m\n ┃\n ┗━Scan Completed in \x1b[1m\x1b[36m0.32\x1b[0m Seconds, using \x1b[1m\x1b[36m1\x1b[0m Requests\n\n\n\n\x1b[1m\x1b[91m CMSeeK says ~ Aabar dekha hobey\x1b[0m\n'
# >>> m = re.search('CMS:\s*\\x1b\[1m\\x1b\[32mDrupal\\x1b\[0m.*?Version: \\x1b\[1m\\x1b\[32m(?P<version>[0-9.]+)?\\x1b', text, re.DOTALL)
# >>> m
# <_sre.SRE_Match object; span=(1441, 1504), match='CMS: \x1b[1m\x1b[32mDrupal\x1b[0m\n ┃    │\n ┃   >
# >>> m = re.search('CMS:\s*\\x1b\[1m\\x1b\[32mDrupal\\x1b\[0m.*?Version: \\x1b\[1m\\x1b\[32m(?P<version>[0-9.]+)?\\x1b', text, re.DOTALL)
# >>> m
# <_sre.SRE_Match object; span=(1441, 1504), match='CMS: \x1b[1m\x1b[32mDrupal\x1b[0m\n ┃    │\n ┃   >

WEB_CMS_FINGERPRINTS = {
'3dcart': {
    'wappalyzer': '3dCart',
},
'Advanced Electron Forum': {},
'Afosto': {},
'Afterbuy': {
    'wappalyzer': 'AfterBuy',
},
'Ametys Cms': {
    'wappalyzer': 'Ametys',
},
'Apostrophe Cms': {},
'Arastta': {
    'wappalyzer': 'Arastta',
},
'AsciiDoc': {
    'wappalyzer': 'AsciiDoc',
},
'Aspnetforum': {},
'Beehive Forum': {},
'Bigcommerce': {
    'wappalyzer': 'Bigcommerce',
},
'Bigware Shop': {
    'wappalyzer': 'Bigware',
},
'Bizweb': {},
'Bolt': {
    'wappalyzer': 'Bolt',
},
'Browsercms': {
    'wappalyzer': 'BrowserCMS',
},
'Bubble': {
    'wappalyzer': 'Bubble',
},
'Burning Board': {
    'wappalyzer': 'Burning Board',
},
'Adobe/Business Catalyst': {
    'wappalyzer': 'Business Catalyst',
},
'Ckan': {
    'wappalyzer': 'Ckan',
},
'Clientexec': {
    'wappalyzer': 'Clientexec',
},
'Cloudcart': {
    'wappalyzer': 'CloudCart',
},
'Colormeshop': {},
'Contao Cms': {
    'wappalyzer': 'Contao',
},
'Contendio': {
    'wappalyzer': 'Contenido',
},
'Contensis Cms': {
    'wappalyzer': 'Contens',
},
'Contentbox': {
    'wappalyzer': 'ContentBox',
},
'Contentful': {},
'Cpg Dragonfly Cms': {
    'wappalyzer': 'CPG Dragonfly',
},
'Cotonti Siena': {
    'wappalyzer': 'Cotonti',
},
'Craft Cms': {
    'wappalyzer': 'Craft CMS',
},
'Danneo/Cms': {
    'wappalyzer': 'Danneo CMS',
},
'Sitecore/Cms': {
    'wappalyzer': 'Sitecore',
},
'Cms Made Simple': {
    'wappalyzer': 'CMS Made Simple',
},
'Cmsimple': {
    'wappalyzer': 'CMSimple',
},
'Concrete5': {
    'wappalyzer': 'Concrete5',
},
'Dedecms': {
    'wappalyzer': 'DedeCMS',
},
'Discourse': {
    'wappalyzer': 'Discourse',
},
'Discuz': {
    'wappalyzer': 'Discuz! X',
},
'Django Cms': {
    'wappalyzer': 'Django CMS',
},
'Dokuwiki': {
    'wappalyzer': 'DokuWiki',
},
'Dotcms': {},
'Dotnetnuke': {
    'wappalyzer': 'DNN',
},
'Drupal': {
    'wappalyzer': 'Drupal',
},
'E107': {
    'wappalyzer': 'e107',
},
'Episerver': {
    'wappalyzer': 'EPiServer',
},
'Expressionengine': {
    'wappalyzer': 'ExpressionEngine',
},
'Ez Publish': {
    'wappalyzer': 'eZ Publish',
},
'Flarum': {},
'Flexcmp': {
    'wappalyzer': 'FlexCMP',
},
'Fluxbb': {
    'wappalyzer': 'FluxBB',
},
'Fork Cms': {},
'Fudforum': {},
'Getsimple Cms': {
    'wappalyzer': 'GetSimple CMS',
},
'Ghost Cms': {
    'wappalyzer': 'Ghost',
},
'Gravcms': {
    'wappalyzer': 'Grav',
},
'Hippo Cms': {
    'wappalyzer': 'Hippo',
},
'Hotaru Cms': {
    'wappalyzer': 'Hotaru CMS',
},
'Impresspages Cms': {
    'wappalyzer': 'ImpressPages',
},
'Indexhibit': {
    'wappalyzer': 'Indexhibit',
},
'Invision Power Board': {
    'wappalyzer': 'IPB',
},
'Jalios Jcms': {
    'wappalyzer': 'Jalios',
},
'Jimdo': {
    'wappalyzer': 'Jimdo',
},
'Jforum': {},
'Joomla': {
    'wappalyzer': 'Joomla',
},
'Koken': {
    'wappalyzer': 'Koken',
},
'Kooboo Cms': {
    'wappalyzer': 'Kooboo CMS',
},
'Lepton-cms/Lepton': {
    'wappalyzer': 'LEPTON',
},
'Liferay': {
    'wappalyzer': 'Liferay',
},
'Livejournal': {
    'wappalyzer': 'LiveJournal',
},
'Livestreet': {
    'wappalyzer': 'LiveStreet CMS',
},
'Magento': {
    'wappalyzer': 'Magento',
},
'Majordomo': {},
'Mambo': {
    'wappalyzer': 'Mambo',
},
'Squiz/Matrix': {
    'wappalyzer': 'Squiz Matrix',
},
'Mediawiki': {
    'wappalyzer': 'MediaWiki',
},
'Minibb': {
    'wappalyzer': 'MiniBB',
},
'Mercuryboard': {},
'Modx Revolution': {
    'wappalyzer': 'MODX',
},
'Moodle': {
    'wappalyzer': 'Moodle',
},
'Moto Cms': {
    'wappalyzer': 'MotoCMS',
},
'Movable Type': {
    'wappalyzer': 'Movable Type',
},
'Mura Cms': {
    'wappalyzer': 'Mura CMS',
},
'Mvnforum': {},
'Mwforum': {},
'Mybb': {
    'wappalyzer': 'MyBB',
},
'Nodebb': {},
'NoNonsense Forum': {},
'October Cms': {
    'wappalyzer': 'October CMS',
},
'Odoo': {
    'wappalyzer': 'Odoo',
},
'Opencart': {
    'wappalyzer': 'OpenCart',
},
'Opencms': {
    'wappalyzer': 'OpenCms',
},
'Opentext Wsm': {
    'wappalyzer': 'OpenText Web Solutions',
},
'Ophal': {
    'wappalyzer': 'Ophal',
},
'Orchard': {
    'wappalyzer': 'Orchard CMS',
},
'Pencilblue': {
    'wappalyzer': 'PencilBlue',
},
'Percussion Cms': {
    'wappalyzer': 'Percussion',
},
'Phorum': {},
'Php-nuke': {
    'wappalyzer': 'PHP-Nuke',
},
'Phpbb': {
    'wappalyzer': 'phpBB',
},
'Phpcms': {
    'wappalyzer': 'phpCMS',
},
'Phpmyadmin': {
    'wappalyzer': 'phpMyAdmin',
},
'Phppgadmin': {
    'wappalyzer': 'phpPgAdmin',
},
'Phpwind': {},
'Pimcore': {
    'wappalyzer': 'Pimcore',
},
'Plone': {
    'wappalyzer': 'Plone',
},
'Presstopia': {},
'Prestashop': {
    'wappalyzer': 'PrestaShop',
},
'Punbb': {
    'wappalyzer': 'punBB',
},
'Quick.cms': {
    'wappalyzer': 'Quick.CMS',
},
'Rcms': {
    'wappalyzer': 'RCMS',
},
'Ritecms': {
    'wappalyzer': 'RiteCMS',
},
'Roadiz Cms': {
    'wappalyzer': 'Roadiz CMS',
},
'Rock Rms': {
    'wappalyzer': 'RockRMS',
},
'Roundcube Webmail': {
    'wappalyzer': 'RoundCube',
},
'Seamlesscms': {},
'Serendipity': {
    'wappalyzer': 'Serendipity',
},
'Sharepoint': {
    'wappalyzer': 'Microsoft SharePoint',
},
'Silva': {
    'wappalyzer': 'Silva',
},
'Silverstripe': {
    'wappalyzer': 'SilverStripe',
},
'Simple Machines Forum': {},
'Sitecore': {
    'wappalyzer': 'Sitecore',
},
'Sitefinity': {
    'wappalyzer': 'Sitefinity',
},
'Snews': {
    'wappalyzer': 'sNews',
},
'Solodev': {
    'wappalyzer': 'Solodev',
},
'Spin Cms': {},
'Squirrelmail': {
    'wappalyzer': 'SquirrelMail',
},
'Subrion Cms': {
    'wappalyzer': 'Subrion',
},
'Sulu': {
    'wappalyzer': 'Sulu',
},
'Textpattern': {
    'wappalyzer': 'Textpattern CMS',
},
'Tiddlywiki': {
    'wappalyzer': 'TiddlyWiki',
},
'Tikiwiki': {
    'wappalyzer': 'Tiki Wiki CMS Groupware',
},
'Typo3': {
    'wappalyzer': 'TYPO3 CMS',
},
'UBB.threads': {},
'Uknowva': {
    'wappalyzer': 'uKnowva',
},
'Ultimate Php Board': {},
'Ushahidi Platform': {
    'wappalyzer': 'Ushahidi',
},
'Umbraco': {
    'wappalyzer': 'Umbraco',
},
'Umi Cms': {},
'Vanilla Forums': {
    'wappalyzer': 'Vanilla',
},
'Vbulletin': {
    'wappalyzer': 'vBulletin',
},
'Webflow Cms': {},
'Webgui': {
    'wappalyzer': 'WebGUI',
},
'Websitebaker': {
    'wappalyzer': 'WebsiteBaker',
},
'Wolf Cms': {
    'wappalyzer': 'Wolf CMS',
},
'Wordpress': {
    'wappalyzer': 'WordPress',
},
'Xenforo': {
    'wappalyzer': 'XenForo',
},
'Xmb': {
    'wappalyzer': 'XMB',
},
'Xoops': {
    'wappalyzer': 'XOOPS',
},
'Yabb': {
    'wappalyzer': 'YaBB',
},
'Yazd Discussion Forum': {},
'Yet Another Forum.net': {},
'Zen Cart': {
    'wappalyzer': 'Zen Cart',
},
'Zen Photos': {},
}
