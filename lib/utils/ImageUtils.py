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
    	Create a thumbnail from an image (ratio is kept).

    	:param bytearray source: Source image as binary data
    	:param int width: Requested max width for thumbnail
    	:param int height: Requested max height for thumbnail
    	:return: Thumbnail as binary data
    	:rtype: BytesIO|None
    	"""
    	size = width, height

    	try:
			image = Image.open(io.BytesIO(source))
			image.thumbnail(size, Image.ANTIALIAS)
			thumb = io.BytesIO()
			image.save(thumb)
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
            image.save(filepath)
        except:
            return False
        return True