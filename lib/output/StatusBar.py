# -*- coding: utf-8 -*-
###
### Output > StatusBar
###
import enlighten
import sys
import time
from lib.output.Output import Output

# enlighten module API reference:
# https://python-enlighten.readthedocs.io/en/latest/api.html

STATUSBAR_FORMAT = Output.colored('{desc}{desc_pad}|{percentage:3.0f}% |{bar}| [{elapsed}]', 
                                  color='white', highlight='navy_blue')
STATUSBAR_FORMAT_SINGLE = Output.colored('{desc}{desc_pad}{fill}', 
                                  color='white', highlight='navy_blue')

DESC_LENGTH = 81

# By default enlighten does not take into account special chars used for coloration in
# the format (by colored module), a dirty hack consists in re-adjusting the terminal
# width in manager.width by adding a correct value (24).
# It is also necessary to override the method manager._resize_handler which is called 
# each time the window is resized, in order to make sure the width is corrected
HACK_LENGTH = 24 

# Subclassing Manager class from
# https://github.com/Rockhopper-Technologies/enlighten/blob/master/enlighten/_manager.py
class MyManager(enlighten.Manager):

    def _resize_handler(self, *args, **kwarg):  # pylint: disable=unused-argument
        """
        Called when a window resize signal is detected
        Resets the scroll window
        """

        # Make sure only one resize handler is running
        try:
            assert self.resize_lock
        except AssertionError:

            self.resize_lock = True
            term = self.term

            term.clear_cache()
            newHeight = term.height
            newWidth = term.width+HACK_LENGTH # correct the width
            lastHeight = lastWidth = 0

            while newHeight != lastHeight or newWidth != lastWidth:
                lastHeight = newHeight
                lastWidth = newWidth
                time.sleep(.2)
                term.clear_cache()
                newHeight = term.height
                newWidth = term.width+HACK_LENGTH # correct the width

            if newWidth < self.width:
                offset = (self.scroll_offset - 1) * (1 + self.width // newWidth)
                term.move_to(0, max(0, newHeight - offset))
                self.stream.write(term.clear_eos)

            self.width = newWidth
            self._set_scroll_area(force=True)

            for cter in self.counters:
                cter.refresh(flush=False)
            self.stream.flush()

            self.resize_lock = False


# Adapting code from get_manager()
stream = sys.stdout
isatty = hasattr(stream, 'isatty') and stream.isatty()
kwargs = {}
kwargs['enabled'] = isatty and kwargs.get('enabled', True)
manager = MyManager(stream=stream, counterclass=enlighten.Counter, **kwargs)
#manager = enlighten.get_manager()
manager.width += HACK_LENGTH # hack to fill the whole line

