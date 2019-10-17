#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Jok3r update
###
import git
import sys

from lib.core.Config import *
from lib.core.ProcessLauncher import ProcessLauncher
from lib.core.Settings import Settings
from lib.output.Logger import logger
from lib.output.Output import Output
from lib.utils.NetUtils import NetUtils


if __name__ == '__main__':
    print(BANNER)
    Output.title1('Update Jok3r')
    logger.info('This script will update Jok3r to the latest available version.')
    logger.info('It will install newly added tools in the toolbox, and will re-install')
    logger.info('tools for which install/update commands have changed in settings. ')
    logger.info('It will also make sure to install new dependencies if needed.')

    print()
    Output.title2('Step #0: Check Internet connection...')
    if NetUtils.is_internet_connected():
        logger.success('Connected to Internet, will continue')
    else:
        logger.error('Not connected to Internet, cannot continue !')
        sys.exit(1)

    #------------------------------------------------------------------------------------
    print()
    Output.title2('Step #1: Save current settings...')
    try:
        settings_bak = Settings()
    except Exception as e:
        logger.error('An error occured when saving current settings: {}'.format(e))
        sys.exit(1)
    logger.success('Current settings saved')

    #------------------------------------------------------------------------------------
    print()
    Output.title2('Step #2: Update source code from master branch at ' \
        'https://github.com/koutto/jok3r ...')
    try:
        g = git.cmd.Git('.')
        gitoutput = g.pull()
    except Exception as e:
        logger.error('An error occured while performing "git pull": {}'.format(e))
        sys.exit(1)
    logger.info('git pull output:')
    print(gitoutput)
    print()
    if gitoutput == 'Already up to date.':
        logger.success('Jok3r is already up-to-date !')
        sys.exit(0)

    #------------------------------------------------------------------------------------
    print()
    Output.title2('Step #3: Install new dependencies if needed ...')
    if 'install-dependencies.sh' in gitoutput:
        logger.info('install-dependencies.sh has been updated. Will re-run it...')
        returncode, _ = ProcessLauncher('./install-dependencies.sh').start()
        if returncode != 0:
            logger.error('An error occured during execution of ' \
                'install-dependencies.sh (exitcode = {})'.format(returncode))
            sys.exit(1)
        else:
            logger.success('install-dependencies.sh finished with success returncode')

    elif 'requirements.txt' in gitoutput:
        # If install-dependencies has been run, no need to be here because it already
        # runs install of required libraries
        logger.info('requirements.txt has been updated. Will install python ' \
            'libraries...') 
        returncode, _ = ProcessLauncher('pip3 install -r requirements.txt').start()
        if returncode != 0:
            logger.error('An error occured during execution of "pip3 install ' \
                'requirements.txt" (exitcode = {})'.format(returncode))
            sys.exit(1)
        else:
            logger.success('"pip3 install requirements.txt" finished with success ' \
                'returncode')        

    else:
        logger.info('No change in dependencies to install')

    #------------------------------------------------------------------------------------
    print()
    Output.title2('Step #4: Perform toolbox diff...')
    if '{}{}'.format(TOOLBOX_CONF_FILE, CONF_EXT) not in gitoutput:
        logger.info('Toolbox settings ({}{}) has not been updated, no further check ' \
            'needed'.format(TOOLBOX_CONF_FILE, CONF_EXT))
    else:
        logger.info('Toolbox settings ({}{}) updated. Load new settings...'.format(
            TOOLBOX_CONF_FILE, CONF_EXT))
        try:
            settings_new = Settings()
        except Exception as e:
            logger.error('An error occured when loading new settings: {}'.format(e))
            sys.exit(1)

        diff = settings_bak.toolbox.compare_with_new(settings_new.toolbox)
        logger.info('Toolbox diff results:')
        logger.info('- {} new tools added'.format(len(diff['new'])))
        for tool in diff['new']:
            logger.info('  +-> {}'.format(tool))
        logger.info('- {} tools with updated configuration'.format(len(diff['updated'])))
        for tool in diff['updated']:
            logger.info('  +-> {}'.format(tool))
        logger.info('- {} tools deleted'.format(len(diff['deleted'])))
        for tool in diff['deleted']:
            logger.info('  +-> {}'.format(tool))

        if len(diff['new']) == 0 \
           and len(diff['updated']) == 0 \
           and len(diff['deleted']) == 0:
            logger.info('No change in toolbox settings detected')
            toolbox_change = False
        else:
            toolbox_change = True

    #------------------------------------------------------------------------------------
    print()
    Output.title2('Step #5: Update toolbox according to the diff...')
    if not toolbox_change:
        logger.info('Skipped because no change in toolbox settings detected')
    else:
        logger.info('Note: This will not update all tools, just re-install tools with ' \
            'updated configuration,')
        logger.info('install newly added tools and delete tools removed from settings ' \
            'if needed.')

        if len(diff['new']) > 0:
            logger.info('Install newly added tools...')
            for tool in diff['new']:
                if not settings_new.toolbox.install_tool(tool, fast_mode=True):
                    logger.error('An error occured during tool "{}" install. ' \
                        'Exit'.format(tool))
                    sys.exit(1)

        if len(diff['updated']) > 0:
            logger.info('Re-install tools with updated configuration...')
            for tool in diff['updated']:
                settings_new.toolbox.remove_tool(tool)
                if not settings_new.toolbox.install_tool(tool, fast_mode=True):
                    logger.error('An error occured during tool "{}" re-install. ' \
                        'Exit'.format(tool))
                    sys.exit(1)

        if len(diff['deleted']) > 0:
            logger.info('Delete tools removed from toolbox settings...')
            for tool in diff['deleted']:
                settings_bak.toolbox.remove_tool(tool)

    #------------------------------------------------------------------------------------
    print()
    logger.success('Update script finished with success')
    sys.exit(0)