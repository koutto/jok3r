# -*- coding: utf-8 -*-
###
### SmartModules > Fingerprints > WebCmsFingerprint
###


# m = re.search('CMS: Joomla(.*Version: (?P<version>[0-9.]+)?)?', textjoomla, re.DOTALL)
# m = re.search('CMS: Microsoft Sharepoint(.*Version: (?P<version>[0-9.]+)?)?', text, re.DOTALL)

CMSEEK_REGEXP = 'CMS: {}(.*Version: [VERSION])?'

WEB_CMS_FINGERPRINTS = {
'3dcart': {
    'wappalyzer': '3dCart',
    'cmseek': CMSEEK_REGEXP.format('3dCart'),
},
'Advanced Electron Forum': {
    'cmseek': CMSEEK_REGEXP.format('Advanced Electron Forum'),
},
'Afosto': {
    'cmseek': CMSEEK_REGEXP.format('Afosto'),
},
'Afterbuy': {
    'wappalyzer': 'AfterBuy',
    'cmseek': CMSEEK_REGEXP.format('Afterbuy'),
},
'Ametys Cms': {
    'wappalyzer': 'Ametys',
    'cmseek': CMSEEK_REGEXP.format('Ametys CMS'),
},
'Apostrophe Cms': {
    'cmseek': CMSEEK_REGEXP.format('Apostrophe CMS'),
},
'Arastta': {
    'wappalyzer': 'Arastta',
    'cmseek': CMSEEK_REGEXP.format('Arastta'),
},
'AsciiDoc': {
    'wappalyzer': 'AsciiDoc',
    'cmseek': CMSEEK_REGEXP.format('AsciiDoc'),
},
'Aspnetforum': {
    'cmseek': CMSEEK_REGEXP.format('AspNetForum'),
},
'Beehive Forum': {
    'cmseek': CMSEEK_REGEXP.format('Beehive Forum'),
},
'Bigcommerce': {
    'wappalyzer': 'Bigcommerce',
    'cmseek': CMSEEK_REGEXP.format('BigCommerce'),
},
'Bigware Shop': {
    'wappalyzer': 'Bigware',
    'cmseek': CMSEEK_REGEXP.format('Bigware'),
},
'Bizweb': {
    'cmseek': CMSEEK_REGEXP.format('Bizweb'),
},
'Bolt': {
    'wappalyzer': 'Bolt',
    'cmseek': CMSEEK_REGEXP.format('Bolt'),
},
'Browsercms': {
    'wappalyzer': 'BrowserCMS',
    'cmseek': CMSEEK_REGEXP.format('BrowserCMS'),
},
'Bubble': {
    'wappalyzer': 'Bubble',
    'cmseek': CMSEEK_REGEXP.format('Bubble'),
},
'Burning Board': {
    'wappalyzer': 'Burning Board',
    'cmseek': CMSEEK_REGEXP.format('Burning Board'),
},
'Adobe/Business Catalyst': {
    'wappalyzer': 'Business Catalyst',
    'cmseek': CMSEEK_REGEXP.format('Adobe Business Catalyst'),
},
'Ckan': {
    'wappalyzer': 'Ckan',
    'cmseek': CMSEEK_REGEXP.format('CKAN'),
},
'Clientexec': {
    'wappalyzer': 'Clientexec',
    'cmseek': CMSEEK_REGEXP.format('Clientexec'),
},
'Cloudcart': {
    'wappalyzer': 'CloudCart',
    'cmseek': CMSEEK_REGEXP.format('Cloudcart'),
},
'Colormeshop': {
    'cmseek': CMSEEK_REGEXP.format('ColorMeShop'),
},
'Contao Cms': {
    'wappalyzer': 'Contao',
},
'Contendio': {
    'wappalyzer': 'Contenido',
},
'Contensis Cms': {
    'wappalyzer': 'Contens',
    'cmseek': CMSEEK_REGEXP.format('Contensis CMS'),
},
'Contentbox': {
    'wappalyzer': 'ContentBox',
    'cmseek': CMSEEK_REGEXP.format('ContentBox'),
},
'Contentful': {
    'cmseek': CMSEEK_REGEXP.format('Contentful'),
},
'Cpg Dragonfly Cms': {
    'wappalyzer': 'CPG Dragonfly',
    'cmseek': CMSEEK_REGEXP.format('CPG Dragonfly'),
},
'Cotonti Siena': {
    'wappalyzer': 'Cotonti',
    'cmseek': CMSEEK_REGEXP.format('Cotonti'),
},
'Craft Cms': {
    'wappalyzer': 'Craft CMS',
    'cmseek': CMSEEK_REGEXP.format('Craft CMS'),
},
'Danneo/Cms': {
    'wappalyzer': 'Danneo CMS',
    'cmseek': CMSEEK_REGEXP.format('Danneo CMS'),
},
'Sitecore/Cms': {
    'wappalyzer': 'Sitecore',
    'cmseek': CMSEEK_REGEXP.format('Sitecore'),
},
'Cms Made Simple': {
    'wappalyzer': 'CMS Made Simple',
    'cmseek': CMSEEK_REGEXP.format('CMS Made Simple'),
},
'Cmsimple': {
    'wappalyzer': 'CMSimple',
    'cmseek': CMSEEK_REGEXP.format('CMSimple'),
},
'Concrete5': {
    'wappalyzer': 'Concrete5',
    'cmseek': CMSEEK_REGEXP.format('Concrete5 CMS'),
},
'Dedecms': {
    'wappalyzer': 'DedeCMS',
    'cmseek': CMSEEK_REGEXP.format('DEDE CMS'),
},
'Discourse': {
    'wappalyzer': 'Discourse',
    'cmseek': CMSEEK_REGEXP.format('Discourse'),
},
'Discuz': {
    'wappalyzer': 'Discuz! X',
    'cmseek': CMSEEK_REGEXP.format('Discuz!'),
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
    'cmseek': CMSEEK_REGEXP.format('DNN Platform'),
},
'Drupal': {
    'wappalyzer': 'Drupal',
    'cmseek': CMSEEK_REGEXP.format('Drupal'),
},
'E107': {
    'wappalyzer': 'e107',
    'cmseek': CMSEEK_REGEXP.format('e107'),
},
'Episerver': {
    'wappalyzer': 'EPiServer',
    'cmseek': CMSEEK_REGEXP.format('EPiServer'),
},
'Expressionengine': {
    'wappalyzer': 'ExpressionEngine',
    'cmseek': CMSEEK_REGEXP.format('ExpressionEngine'),
},
'Ez Publish': {
    'wappalyzer': 'eZ Publish',
    'cmseek': CMSEEK_REGEXP.format('eZ Publish'),
},
'Flarum': {
    'cmseek': CMSEEK_REGEXP.format('Flarum'),
},
'Flexcmp': {
    'wappalyzer': 'FlexCMP',
    'cmseek': CMSEEK_REGEXP.format('FlexCMP'),
},
'Fluxbb': {
    'wappalyzer': 'FluxBB',
    'cmseek': CMSEEK_REGEXP.format('FluxBB'),
},
'Fork Cms': {
    'cmseek': CMSEEK_REGEXP.format('Fork CMS'),
},
'Fudforum': {
    'cmseek': CMSEEK_REGEXP.format('FUDforum'),
},
'Getsimple Cms': {
    'wappalyzer': 'GetSimple CMS',
    'cmseek': CMSEEK_REGEXP.format('GetSimple CMS'),
},
'Ghost Cms': {
    'wappalyzer': 'Ghost',
    'cmseek': CMSEEK_REGEXP.format('Ghost CMS'),
},
'Gravcms': {
    'wappalyzer': 'Grav',
    'cmseek': CMSEEK_REGEXP.format('GravCMS'),
},
'Hippo Cms': {
    'wappalyzer': 'Hippo',
    'cmseek': CMSEEK_REGEXP.format('HIPPO CMS'),
},
'Hotaru Cms': {
    'wappalyzer': 'Hotaru CMS',
    'cmseek': CMSEEK_REGEXP.format('Hotaru CMS'),
},
'Impresspages Cms': {
    'wappalyzer': 'ImpressPages',
    'cmseek': CMSEEK_REGEXP.format('ImpressPages CMS'),
},
'Indexhibit': {
    'wappalyzer': 'Indexhibit',
    'cmseek': CMSEEK_REGEXP.format('Indexhibit'),
},
'Invision Power Board': {
    'wappalyzer': 'IPB',
    'cmseek': CMSEEK_REGEXP.format('IP.Board community forum'),
},
'Jalios Jcms': {
    'wappalyzer': 'Jalios',
    'cmseek': CMSEEK_REGEXP.format('Jalios JCMS'),
},
'Jimdo': {
    'wappalyzer': 'Jimdo',
    'cmseek': CMSEEK_REGEXP.format('Jimdo'),
},
'Jforum': {
    'cmseek': CMSEEK_REGEXP.format('JForum'),
},
'Joomla': {
    'wappalyzer': 'Joomla',
    'cmseek': CMSEEK_REGEXP.format('Joomla'),
},
'Koken': {
    'wappalyzer': 'Koken',
    'cmseek': CMSEEK_REGEXP.format('Koken'),
},
'Kooboo Cms': {
    'wappalyzer': 'Kooboo CMS',
    'cmseek':CMSEEK_REGEXP.format('Kooboo CMS'),
},
'Lepton-cms/Lepton': {
    'wappalyzer': 'LEPTON',
    'cmseek': CMSEEK_REGEXP.format('LEPTON CMS'),
},
'Liferay': {
    'wappalyzer': 'Liferay',
},
'Livejournal': {
    'wappalyzer': 'LiveJournal',
    'cmseek': CMSEEK_REGEXP.format('LiveJournal'),
},
'Livestreet': {
    'wappalyzer': 'LiveStreet CMS',
    'cmseek': CMSEEK_REGEXP.format('LiveStreet CMS'),
},
'Magento': {
    'wappalyzer': 'Magento',
    'cmseek': CMSEEK_REGEXP.format('Magento'),
},
'Majordomo': {},
'Mambo': {
    'wappalyzer': 'Mambo',
    'cmseek': CMSEEK_REGEXP.format('Mambo'),
},
'Squiz/Matrix': {
    'wappalyzer': 'Squiz Matrix',
    'cmseek': CMSEEK_REGEXP.format('Squiz Matrix'),
},
'Mediawiki': {
    'wappalyzer': 'MediaWiki',
},
'Minibb': {
    'wappalyzer': 'MiniBB',
    'cmseek': CMSEEK_REGEXP.format('miniBB'),
},
'Mercuryboard': {
    'cmseek': CMSEEK_REGEXP.format('MercuryBoard'),
},
'Modx Revolution': {
    'wappalyzer': 'MODX',
    'cmseek': CMSEEK_REGEXP.format('MODX'),
},
'Moodle': {
    'wappalyzer': 'Moodle',
},
'Moto Cms': {
    'wappalyzer': 'MotoCMS',
    'cmseek': CMSEEK_REGEXP.format('Moto CMS'),
},
'Movable Type': {
    'wappalyzer': 'Movable Type',
},
'Mura Cms': {
    'wappalyzer': 'Mura CMS',
    'cmseek': CMSEEK_REGEXP.format('Mura CMS'),
},
'Mvnforum': {
    'cmseek': CMSEEK_REGEXP.format('mvnForum'),
},
'Mwforum': {
    'cmseek': CMSEEK_REGEXP.format('mwForum'),
},
'Mybb': {
    'wappalyzer': 'MyBB',
    'cmseek': CMSEEK_REGEXP.format('MyBB'),
},
'Nodebb': {
    'cmseek': CMSEEK_REGEXP.format('NodeBB'),
},
'NoNonsense Forum': {
    'cmseek': CMSEEK_REGEXP.format('NoNonsense Forum'),
},
'October Cms': {
    'wappalyzer': 'October CMS',
    'cmseek': CMSEEK_REGEXP.format('October CMS'),
},
'Odoo': {
    'wappalyzer': 'Odoo',
    'cmseek': CMSEEK_REGEXP.format('Odoo'),
},
'Opencart': {
    'wappalyzer': 'OpenCart',
    'cmseek': CMSEEK_REGEXP.format('OpenCart'),
},
'Opencms': {
    'wappalyzer': 'OpenCms',
    'cmseek': CMSEEK_REGEXP.format('OpenCms'),
},
'Opentext Wsm': {
    'wappalyzer': 'OpenText Web Solutions',
    'cmseek': CMSEEK_REGEXP.format('OpenText WSM'),
},
'Ophal': {
    'wappalyzer': 'Ophal',
    'cmseek': CMSEEK_REGEXP.format('Ophal'),
},
'Orchard': {
    'wappalyzer': 'Orchard CMS',
    'cmseek': CMSEEK_REGEXP.format('Orchard CMS'),
},
'Pencilblue': {
    'wappalyzer': 'PencilBlue',
    'cmseek': CMSEEK_REGEXP.format('PencilBlue'),
},
'Percussion Cms': {
    'wappalyzer': 'Percussion',
    'cmseek': CMSEEK_REGEXP.format('Percussion CMS'),
},
'Phorum': {
    'cmseek': CMSEEK_REGEXP.format('Phorum'),
},
'Php-nuke': {
    'wappalyzer': 'PHP-Nuke',
    'cmseek': CMSEEK_REGEXP.format('PHP Nuke'),
},
'Phpbb': {
    'wappalyzer': 'phpBB',
    'cmseek': CMSEEK_REGEXP.format('phpBB'),
},
'Phpcms': {
    'wappalyzer': 'phpCMS',
    'cmseek': CMSEEK_REGEXP.format('phpCMS'),
},
'Phpmyadmin': {
    'wappalyzer': 'phpMyAdmin',
},
'Phppgadmin': {
    'wappalyzer': 'phpPgAdmin',
},
'Phpwind': {
    'cmseek': CMSEEK_REGEXP.format('phpWind'),
},
'Pimcore': {
    'wappalyzer': 'Pimcore',
    'cmseek': CMSEEK_REGEXP.format('Pimcore'),
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
    'cmseek': CMSEEK_REGEXP.format('PunBB'),
},
'Quick.cms': {
    'wappalyzer': 'Quick.CMS',
    'cmseek': CMSEEK_REGEXP.format('Quick.Cms'),
},
'Rcms': {
    'wappalyzer': 'RCMS',
    'cmseek': CMSEEK_REGEXP.format('RCMS'),
},
'Ritecms': {
    'wappalyzer': 'RiteCMS',
    'cmseek': CMSEEK_REGEXP.format('RiteCMS'),
},
'Roadiz Cms': {
    'wappalyzer': 'Roadiz CMS',
    'cmseek': CMSEEK_REGEXP.format('Roadiz CMS'),
},
'Rock Rms': {
    'wappalyzer': 'RockRMS',
    'cmseek': CMSEEK_REGEXP.format('Rock RMS'),
},
'Roundcube Webmail': {
    'wappalyzer': 'RoundCube',
},
'Seamlesscms': {
    'cmseek': CMSEEK_REGEXP.format('SeamlessCMS'),
},
'Serendipity': {
    'wappalyzer': 'Serendipity',
    'cmseek': CMSEEK_REGEXP.format('Serendipity'),
},
'Sharepoint': {
    'wappalyzer': 'Microsoft SharePoint',
    'cmseek': CMSEEK_REGEXP.format('Microsoft Sharepoint'),
},
'Silva': {
    'wappalyzer': 'Silva',
    'cmseek': CMSEEK_REGEXP.format('Silva CMS'),
},
'Silverstripe': {
    'wappalyzer': 'SilverStripe',
    'cmseek': CMSEEK_REGEXP.format('SilverStripe'),
},
'Simple Machines Forum': {
    'cmseek': CMSEEK_REGEXP.format('Simple Machines Forum'),
},
'Sitecore': {
    'wappalyzer': 'Sitecore',
    'cmseek': CMSEEK_REGEXP.format('Sitecore'),
},
'Sitefinity': {
    'wappalyzer': 'Sitefinity',
    'cmseek': CMSEEK_REGEXP.format('Sitefinity'),
},
'Snews': {
    'wappalyzer': 'sNews',
    'cmseek': CMSEEK_REGEXP.format('sNews'),
},
'Solodev': {
    'wappalyzer': 'Solodev',
    'cmseek': CMSEEK_REGEXP.format('solodev'),
},
'Spin Cms': {
    'cmseek': CMSEEK_REGEXP.format('Spin CMS'),
},
'Squirrelmail': {
    'wappalyzer': 'SquirrelMail',
},
'Subrion Cms': {
    'wappalyzer': 'Subrion',
    'cmseek': CMSEEK_REGEXP.format('Subrion CMS'),
},
'Sulu': {
    'wappalyzer': 'Sulu',
    'cmseek': CMSEEK_REGEXP.format('SULU'),
},
'Textpattern': {
    'wappalyzer': 'Textpattern CMS',
    'cmseek': CMSEEK_REGEXP.format('Textpattern CMS'),
},
'Tiddlywiki': {
    'wappalyzer': 'TiddlyWiki',
    'cmseek': CMSEEK_REGEXP.format('TiddlyWiki'),
},
'Tikiwiki': {
    'wappalyzer': 'Tiki Wiki CMS Groupware',
    'cmseek': CMSEEK_REGEXP.format('Tiki Wiki CMS Groupware'),
},
'Typo3': {
    'wappalyzer': 'TYPO3 CMS',
    'cmseek': CMSEEK_REGEXP.format('TYPO3 CMS'),
},
'UBB.threads': {
    'cmseek': CMSEEK_REGEXP.format('UBB.threads'),
},
'Uknowva': {
    'wappalyzer': 'uKnowva',
    'cmseek': CMSEEK_REGEXP.format('uKnowva'),
},
'Ultimate Php Board': {},
'Ushahidi Platform': {
    'wappalyzer': 'Ushahidi',
    'cmseek': CMSEEK_REGEXP.format('Ushahidi'),
},
'Umbraco': {
    'wappalyzer': 'Umbraco',
},
'Umi Cms': {
    'cmseek': CMSEEK_REGEXP.format('UMI.CMS'),
},
'Vanilla Forums': {
    'wappalyzer': 'Vanilla',
    'cmseek': CMSEEK_REGEXP.format('Vanilla Forums'),
},
'Vbulletin': {
    'wappalyzer': 'vBulletin',
},
'Webflow Cms': {
    'cmseek': CMSEEK_REGEXP.format('Webflow CMS'),
},
'Webgui': {
    'wappalyzer': 'WebGUI',
    'cmseek': CMSEEK_REGEXP.format('WebGUI'),
},
'Websitebaker': {
    'wappalyzer': 'WebsiteBaker',
    'cmseek': CMSEEK_REGEXP.format('WebsiteBaker CMS'),
},
'Wolf Cms': {
    'wappalyzer': 'Wolf CMS',
    'cmseek': CMSEEK_REGEXP.format('Wold CMS'),
},
'Wordpress': {
    'wappalyzer': 'WordPress',
    'cmseek': CMSEEK_REGEXP.format('WordPress'),
},
'Xenforo': {
    'wappalyzer': 'XenForo',
    'cmseek': CMSEEK_REGEXP.format('XenForo'),
},
'Xmb': {
    'wappalyzer': 'XMB',
    'cmseek': CMSEEK_REGEXP.format('XMB'),
},
'Xoops': {
    'wappalyzer': 'XOOPS',
    'cmseek': CMSEEK_REGEXP.format('XOOPS'),
},
'Yabb': {
    'wappalyzer': 'YaBB',
    'cmseek': CMSEEK_REGEXP.format('YaBB \(Yet another Bulletin Board\)'),
},
'Yazd Discussion Forum': {
    'cmseek': CMSEEK_REGEXP.format('Yazd'),
},
'Yet Another Forum.net': {
    'cmseek': CMSEEK_REGEXP.format('Yet Another Forum \(YAF\)'),
},
'Zen Cart': {
    'wappalyzer': 'Zen Cart',
},
'Zen Photos': {},
}
