#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > ImageUtils
###
import io
from PIL import Image


class ImageUtils:

    @staticmethod
    def create_thumbnail(source, width, height):
        """
        Create a thumbnail as binary data from an image (ratio is kept).

        :param bytearray source: Source image as binary data
        :param int width: Requested max width for thumbnail
        :param int height: Requested max height for thumbnail
        :return: Thumbnail as binary data
        :rtype: bytearray|None
        """
        size = width, height

        try:
            image = Image.open(io.BytesIO(source))
            image.thumbnail(size, Image.ANTIALIAS)
            thumbio = io.BytesIO()
            image.save(thumbio, format='PNG')
            thumbio.seek(0) # Important: pointer back to beginning of "memory file"
            thumb = thumbio.read()
        except:
            thumb = None
        return thumb


    @staticmethod
    def save_image(source, filepath):
        """
        Save image as binary to file.

        :param bytearray source: Image as binary data
        :param str filepath: Destination file path
        :return: Boolean indicating status
        :rtype: bool
        """
        try:
            image = Image.open(io.BytesIO(source))
            image.save(filepath, format='PNG')
        except:
            return False
        return True