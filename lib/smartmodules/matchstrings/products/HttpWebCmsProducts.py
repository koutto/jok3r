#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match


# m = re.search('CMS: Joomla(.*Version: (?P<version>[0-9.]+)?)?', textjoomla, re.DOTALL) 
# m = re.search('CMS: Microsoft Sharepoint(.*Version: (?P<version>[0-9.]+)?)?', text, re.DOTALL)



#CMSEEK_REGEXP = 'CMS: {}([\s\S]*Version:\s*[VERSION])?'
CMSEEK_REGEXP = '"cms_name":\s*"{}"(,[\s\S]*"cms_version":\s*"[VERSION]")?'

# Wig output sample:
# Error page detection ...
# - Error page fingerprint: 221fe6d0484f9139410d39c27e52cfe3, 9ec28dbc45cbe7f99dae20a9511fa65a - /
# Determining CMS type ...
# Checking fingerprint group no. 0 ...
# Checking fingerprint group no. 1 ...
# Checking fingerprint group no. 2 ...
# Checking fingerprint group no. 3 ...
# - Found CMS match: WordPress
# Determining CMS version ...
# - Found version: WordPress 4.2.2
# - Found version: WordPress 4.2.1
# - Found version: WordPress 4.2
# - Found version: WordPress 4.1.5
# - Found version: WordPress 4.1.4
# - Found version: WordPress 4.1.3
# - Found version: WordPress 4.1.2
# - Found version: WordPress 4.1.1
WIG_REGEXP = '{}\s*[VERSION]\s*CMS' 
WIG_REGEXP2 = '- Found CMS match: {}\s*(Determining CMS version \.\.\.(\s*- Found version: (\S+)\s+[VERSION])?)?'
WIG_REGEXP3 = '{}\s*[VERSION]\s*Platform' 
WIG_REGEXP4 = '- Found platform {}(\s*[VERSION])?'

products_match['http']['web-cms'] = {
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
        'fingerprinter': '-a cms-made-simple[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
    },
    'Cmsimple': {
        'wappalyzer': 'CMSimple',
        'cmseek': CMSEEK_REGEXP.format('CMSimple'),
    },
    'Concrete5': {
        'wappalyzer': 'Concrete5',
        'cmseek': CMSEEK_REGEXP.format('Concrete5 CMS'),
        'wig': [
            WIG_REGEXP.format('concrete5'),
            WIG_REGEXP2.format('concrete5'),
        ],
        'fingerprinter': '-a concrete5[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
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
        'cmseek': CMSEEK_REGEXP.format('Discuz\!'),
    },
    'Django Cms': {
        'wappalyzer': 'Django CMS',
        'fingerprinter': '-a django-cms[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
    },
    'Dokuwiki': {
        'wappalyzer': 'DokuWiki',
        'wig': [
            WIG_REGEXP.format('DokuWiki'),
            WIG_REGEXP2.format('DokuWiki'),
        ],
    },
    'Dotcms': {
        'wig': [
            WIG_REGEXP.format('dotCMS'),
            WIG_REGEXP2.format('dotCMS'),
        ],
    },
    'Dotnetnuke': {
        'wappalyzer': 'DNN',
        'cmseek': CMSEEK_REGEXP.format('DNN Platform'),
        'wig': [
            WIG_REGEXP.format('DNN \(DotNetNuke\)'),
            WIG_REGEXP2.format('DNN \(DotNetNuke\)'),
        ],
        'fingerprinter': '-a dotnetnuke[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
    },
    'Domino': {
        'wappalyzer': 'Lotus Domino',
        'nmap-banner': 'Lotus Domino(\s*(International|Go))?\s*httpd(\s*[VERSION])?',
        'wig': [
            WIG_REGEXP3.format('Lotus Domino'),
            WIG_REGEXP4.format('Lotus Domino'),
        ],
        'domiowned': 'Domino version:\s*[VERSION]',
    },
    'Drupal': {
        'wappalyzer': 'Drupal',
        'cmseek': CMSEEK_REGEXP.format('Drupal'),
        'wig': [
            WIG_REGEXP.format('Drupal'),
            WIG_REGEXP2.format('Drupal'),
        ],
        'drupwn': 'Version detected: [VERSION]',
        'fingerprinter': '-a drupal[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
        'cmsmap': 'Drupal Version: [VERSION]',
        # Droopescan sample:
        # [+] Possible version(s):
        # 7.57
        # 7.58
        # 7.59
        #'droopescan': '',
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
        'cmseek': CMSEEK_REGEXP.format('IP\.Board community forum'),
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
        'cmseek': '"cms_name":\s*"Joomla"(,[\s\S]*"joomla_version":\s*"[VERSION]")?',
        'wig': [
            WIG_REGEXP.format('Joomla\!'),
            WIG_REGEXP2.format('Joomla\!'),
        ],
        'fingerprinter': '-a joomla[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
        'cmsmap': 'Joomla Version: [VERSION]',
        'joomscan': '\[\+\] Detecting Joomla Version\s*\n\s*\[\+\+\] Joomla [VERSION]',
        'joomlavs': 'Joomla version [VERSION] identified',
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
        'fingerprinter': '-a liferay[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
        'liferayscan': '\+ Version: Liferay .* [VERSION]',
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
        'wig': [
            WIG_REGEXP.format('Magento( (Community|Enterprise) Edition)?'),
            WIG_REGEXP2.format('Magento( (Community|Enterprise) Edition)?'),
        ],
        'fingerprinter': '-a magento[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
        'magescan': 'Version\s+\|\s*[VERSION]',
    },
    'Majordomo': {
        'wig': [
            WIG_REGEXP.format('Majordomo'),
            WIG_REGEXP2.format('Majordomo'),
        ],
    },
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
        'wig': [
            WIG_REGEXP.format('MediaWiki'),
            WIG_REGEXP2.format('MediaWiki'),
        ],
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
        'wig': [
            WIG_REGEXP.format('Moodle'),
            WIG_REGEXP2.format('Moodle'),
        ],
        'fingerprinter': '-a moodle[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
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
        'wig': [
            WIG_REGEXP.format('MyBB'),
            WIG_REGEXP2.format('MyBB'),
        ],
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
        'fingerprinter': '-a opencart[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
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
        'wig': [
            WIG_REGEXP.format('phpMyAdmin'),
            WIG_REGEXP2.format('phpMyAdmin'),
        ],
    },
    'Phppgadmin': {
        'wappalyzer': 'phpPgAdmin',
        'wig': [
            WIG_REGEXP.format('phpPgAdmin'),
            WIG_REGEXP2.format('phpPgAdmin'),
        ],
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
        'wig': [
            WIG_REGEXP.format('Plone'),
            WIG_REGEXP2.format('Plone'),
        ],
    },
    'Presstopia': {
        'wig': [
            WIG_REGEXP.format('Presstopia'),
            WIG_REGEXP2.format('Presstopia'),
        ],
    },
    'Prestashop': {
        'wappalyzer': 'PrestaShop',
        'wig': [
            WIG_REGEXP.format('PrestaShop'),
            WIG_REGEXP2.format('PrestaShop'),
        ],
        'fingerprinter': '-a prestashop[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
    },
    'Punbb': {
        'wappalyzer': 'punBB',
        'cmseek': CMSEEK_REGEXP.format('PunBB'),
        'fingerprinter': '-a punbb[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
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
        'wig': [
            WIG_REGEXP.format('Roundcube'),
            WIG_REGEXP2.format('Roundcube'),
        ],
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
        'wig': [
            WIG_REGEXP.format('SharePoint'),
            WIG_REGEXP2.format('SharePoint'),
        ],
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
        'wig': [
            WIG_REGEXP.format('Sitecore'),
            WIG_REGEXP2.format('Sitecore'),
        ],
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
        'wig': [
            WIG_REGEXP.format('SquirrelMail'),
            WIG_REGEXP2.format('SquirrelMail'),
        ],
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
        'wig': [
            WIG_REGEXP.format('Umbraco'),
            WIG_REGEXP2.format('Umbraco'),
        ],
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
        'wig': [
            WIG_REGEXP.format('vBulletin'),
            WIG_REGEXP2.format('vBulletin'),
        ],
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
        'cmseek': '"cms_name":\s*"WordPress"(,[\s\S]*"wp_version":\s*"[VERSION]")?',
        'wig': [
            WIG_REGEXP.format('WordPress'),
            WIG_REGEXP2.format('WordPress'),
        ],
        'fingerprinter': '-a wordpress[\s\S]*Intersection of potential versions returned only one version v[VERSION]',
        'cmsmap': 'Wordpress Version: [VERSION]',
        'wpscan': 'WordPress version [VERSION] identified',
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
        'wig': [
            WIG_REGEXP.format('XOOPS'),
            WIG_REGEXP2.format('XOOPS'),
        ],
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
        'wig': [
            WIG_REGEXP.format('Zen Cart'),
            WIG_REGEXP2.format('Zen Cart'),
        ],
    },
    'Zen Photos': {
        'wig': [
            WIG_REGEXP.format('Zenphoto'),
            WIG_REGEXP2.format('Zenphoto'),
        ],
    },
}
