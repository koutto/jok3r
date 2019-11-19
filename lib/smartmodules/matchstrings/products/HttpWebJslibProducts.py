#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib.smartmodules.matchstrings.MatchStrings import products_match


WIG_REGEXP = '{}\s*[VERSION]\s*JavaScript' 
WIG_REGEXP2 = '- Found JavaScript: {}(\s*[VERSION])?'


products_match['http']['web-jslib'] = {
    'Angular': {
        'wappalyzer': 'Angular',
    },
    'AngularJS': {
        'wappalyzer': 'AngularJS',
        'wig': [
            WIG_REGEXP.format('AngularJS'),
            WIG_REGEXP2.format('AngularJS'),
        ],
        'angularjs-csti-scanner': '\[INFO\] Found AngularJS version [VERSION]',
    },
    'Backbone.js': {
        'wappalyzer': 'Backbone.js',
    },
    'Dojo': {
        'wappalyzer': 'Dojo',
        'wig': [
            WIG_REGEXP.format('Dojo'),
            WIG_REGEXP2.format('Dojo'),
        ],
    },
    'ef.js': {
        'wappalyzer': 'ef.js',
    },
    'FancyBox': {
        'wappalyzer': 'FancyBox',
    },
    'Handlebars': {
        'wappalyzer': 'Handlebars',
    },
    'Jquery': {
        'wappalyzer': 'jQuery',
        'wig': [
            WIG_REGEXP.format('jQuery'),
            WIG_REGEXP2.format('jQuery'),
        ],
    },
    # 'Jquery UI': {
    #     'wappalyzer': 'jQuery UI',
    # },
    'Lightbox': {
        'wappalyzer': 'Lightbox',
    },
    'Modernizr': {
        'wappalyzer': 'Modernizr',
        'wig': [
            WIG_REGEXP.format('Modernizr'),
            WIG_REGEXP2.format('Modernizr'),
        ],
    },
    'Moment.js': {
        'wappalyzer': 'Moment.js'
    },
    'MooTools': {
        'wappalyzer': 'MooTools',
        'wig': [
            WIG_REGEXP.format('MooTools'),
            WIG_REGEXP2.format('MooTools'),
        ],
    },
    'Mustache.js': {
        'wappalyzer': 'Mustache',
    },
    'Prototype Javascript Framework': {
        'wappalyzer': 'Prototype',
        'wig': [
            WIG_REGEXP.format('Prototype'),
            WIG_REGEXP2.format('Prototype'),
        ],
    },
    'React': {
        'wappalyzer': 'React',
    },
    'RequireJS': {
        'wappalyzer': 'RequireJS',
    },
    'TweenMax': {
        'wappalyzer': 'TweenMax',
    },
    'Underscore.js': {
        'wappalyzer': 'Underscore.js',
    },

    'A-Frame': {
        'wappalyzer': 'A-Frame',
        },
    'AMP': {
        'wappalyzer': 'AMP',
        },
    'Apollo': {
        'wappalyzer': 'Apollo',
        },
    'AlloyUI': {
        'wappalyzer': 'AlloyUI',
        },
    'Ant Design': {
        'wappalyzer': 'Ant Design',
        },
    'Aurelia': {
        'wappalyzer': 'Aurelia',
        },
    'BEM': {
        'wappalyzer': 'BEM',
        },
    'Boba.js': {
        'wappalyzer': 'Boba.js',
        },
    'Bootstrap Table': {
        'wappalyzer': 'Bootstrap Table',
        },
    'Catberry.js': {
        'wappalyzer': 'Catberry.js',
        },
    'Chart.js': {
        'wappalyzer': 'Chart.js',
        },
    'Clipboard.js': {
        'wappalyzer': 'Clipboard.js',
        },
    'D3': {
        'wappalyzer': 'D3',
        },
    'DHTMLX': {
        'wappalyzer': 'DHTMLX',
        },
    'DataTables': {
        'wappalyzer': 'DataTables',
        },
    'Day.js': {
        'wappalyzer': 'Day.js',
        },
    'Element UI': {
        'wappalyzer': 'Element UI',
        },
    'Ember.js': {
        'wappalyzer': 'Ember.js',
        },
    'Enyo': {
        'wappalyzer': 'Enyo',
        },
    'Epoch': {
        'wappalyzer': 'Epoch',
        },
    'Essential JS 2': {
        'wappalyzer': 'Essential JS 2',
        },
    'Exhibit': {
        'wappalyzer': 'Exhibit',
        },
    'ExtJS': {
        'wappalyzer': 'ExtJS',
        },
    'Fingerprintjs': {
        'wappalyzer': 'Fingerprintjs',
        },
    'Flickity': {
        'wappalyzer': 'Flickity',
        },
    'Gatsby': {
        'wappalyzer': 'Gatsby',
        },
    'GoJS': {
        'wappalyzer': 'GoJS',
        },
    'Google Charts': {
        'wappalyzer': 'Google Charts',
        },
    'Hammer.js': {
        'wappalyzer': 'Hammer.js',
        },
    'HeadJS': {
        'wappalyzer': 'HeadJS',
        },
    'Highcharts': {
        'wappalyzer': 'Highcharts',
        },
    'Bokeh': {
        'wappalyzer': 'Bokeh',
        },
    'Highlight.js': {
        'wappalyzer': 'Highlight.js',
        },
    'Highstock': {
        'wappalyzer': 'Highstock',
        },
    'Hogan.js': {
        'wappalyzer': 'Hogan.js',
        },
    'Immutable.js': {
        'wappalyzer': 'Immutable.js',
        },
    'InfernoJS': {
        'wappalyzer': 'InfernoJS',
        },
    'JS Charts': {
        'wappalyzer': 'JS Charts',
        },
    'JavaScript Infovis Toolkit': {
        'wappalyzer': 'JavaScript Infovis Toolkit',
        },
    'Kibana': {
        'wappalyzer': 'Kibana',
        },
    'KineticJS': {
        'wappalyzer': 'KineticJS',
        },
    'Knockout.js': {
        'wappalyzer': 'Knockout.js',
        },
    'Lazy.js': {
        'wappalyzer': 'Lazy.js',
        },
    'List.js': {
        'wappalyzer': 'List.js',
        },
    'Lodash': {
        'wappalyzer': 'Lodash',
        },
    'Marionette.js': {
        'wappalyzer': 'Marionette.js',
        },
    'Marked': {
        'wappalyzer': 'Marked',
        },
    'MathJax': {
        'wappalyzer': 'MathJax',
        },
    'Mean.io': {
        'wappalyzer': 'Mean.io',
        },
    'MediaElement.js': {
        'wappalyzer': 'MediaElement.js',
        },
    'Mermaid': {
        'wappalyzer': 'Mermaid',
        },
    'Meteor': {
        'wappalyzer': 'Meteor',
        },
    'Mithril': {
        'wappalyzer': 'Mithril',
        },
    'MobX': {
        'wappalyzer': 'MobX',
        },
    'MochiKit': {
        'wappalyzer': 'MochiKit',
        },
    'Moment Timezone': {
        'wappalyzer': 'Moment Timezone',
        },
    'Moon': {
        'wappalyzer': 'Moon',
        },
    'NVD3': {
        'wappalyzer': 'NVD3',
        },
    'Next.js': {
        'wappalyzer': 'Next.js',
        },
    'OpenUI5': {
        'wappalyzer': 'OpenUI5',
        },
    'PDF.js': {
        'wappalyzer': 'PDF.js',
        },
    'Paper.js': {
        'wappalyzer': 'Paper.js',
        },
    'Paths.js': {
        'wappalyzer': 'Paths.js',
        },
    'Phaser': {
        'wappalyzer': 'Phaser',
        },
    'Plotly': {
        'wappalyzer': 'Plotly',
        },
    'Polyfill': {
        'wappalyzer': 'Polyfill',
        },
    'Polymer': {
        'wappalyzer': 'Polymer',
        },
    'Protovis': {
        'wappalyzer': 'Protovis',
        },
    'Ramda': {
        'wappalyzer': 'Ramda',
        },
    'Raphael': {
        'wappalyzer': 'Raphael',
        },
    'Reveal.js': {
        'wappalyzer': 'Reveal.js',
        },
    'Rickshaw': {
        'wappalyzer': 'Rickshaw',
        },
    'RightJS': {
        'wappalyzer': 'RightJS',
        },
    'Riot': {
        'wappalyzer': 'Riot',
        },
    'RxJS': {
        'wappalyzer': 'RxJS',
        },
    'Sails.js': {
        'wappalyzer': 'Sails.js',
        },
    'Select2': {
        'wappalyzer': 'Select2',
        },
    'Sencha Touch': {
        'wappalyzer': 'Sencha Touch',
        },
    'Slick': {
        'wappalyzer': 'Slick',
        },
    'Slimbox': {
        'wappalyzer': 'Slimbox',
        },
    'Slimbox 2': {
        'wappalyzer': 'Slimbox 2',
        },
    'Snap.svg': {
        'wappalyzer': 'Snap.svg',
        },
    'Socket.io': {
        'wappalyzer': 'Socket.io',
        },
    'SoundManager': {
        'wappalyzer': 'SoundManager',
        },
    'Strapdown.js': {
        'wappalyzer': 'Strapdown.js',
        },
    'Supersized': {
        'wappalyzer': 'Supersized',
        },
    'Svelte': {
        'wappalyzer': 'Svelte',
        },
    'SweetAlert': {
        'wappalyzer': 'SweetAlert',
        },
    'SweetAlert2': {
        'wappalyzer': 'SweetAlert2',
        },
    'Timeplot': {
        'wappalyzer': 'Timeplot',
        },
    'Transifex': {
        'wappalyzer': 'Transifex',
        },
    'Twitter Flight': {
        'wappalyzer': 'Twitter Flight',
        },
    'Twitter typeahead.js': {
        'wappalyzer': 'Twitter typeahead.js',
        },
    'Vue.js': {
        'wappalyzer': 'Vue.js',
        },
    'Nuxt.js': {
        'wappalyzer': 'Nuxt.js',
        },
    'Webix': {
        'wappalyzer': 'Webix',
        },
    'Wink': {
        'wappalyzer': 'Wink',
        },
    'XRegExp': {
        'wappalyzer': 'XRegExp',
        },
    'Xajax': {
        'wappalyzer': 'Xajax',
        },
    'YUI': {
        'wappalyzer': 'YUI',
        },
    'Zepto': {
        'wappalyzer': 'Zepto',
        },
    'Zone.js': {
        'wappalyzer': 'Zone.js',
        },
    'amCharts': {
        'wappalyzer': 'amCharts',
        },
    'basket.js': {
        'wappalyzer': 'basket.js',
        },
    'jQuery Migrate': {
        'wappalyzer': 'jQuery Migrate',
        },
    'jQuery Sparklines': {
        'wappalyzer': 'jQuery Sparklines',
        },
    'jQuery UI': {
        'wappalyzer': 'jQuery UI',
        },
    'jqPlot': {
        'wappalyzer': 'jqPlot',
        },
    'math.js': {
        'wappalyzer': 'math.js',
        },
    'particles.js': {
        'wappalyzer': 'particles.js',
        },
    'prettyPhoto': {
        'wappalyzer': 'prettyPhoto',
        },
    'script.aculo.us': {
        'wappalyzer': 'script.aculo.us',
        },
    'scrollreveal': {
        'wappalyzer': 'scrollreveal',
        },
    'shine.js': {
        'wappalyzer': 'shine.js',
        },
    'styled-components': {
        'wappalyzer': 'styled-components',
        },
    'three.js': {
        'wappalyzer': 'three.js',
        },
    'total.js': {
        'wappalyzer': 'total.js',
        },
    'xCharts': {
        'wappalyzer': 'xCharts',
        },

}