#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > FileUtils
###
import os
import stat
import shutil
import ntpath


class FileUtils:

    @staticmethod
    def exists(fileName):
        return os.access(fileName, os.F_OK)


    @staticmethod
    def can_read(fileName):
        if not os.access(fileName, os.R_OK):
            return False
        try:
            with open(fileName):
                pass
        except IOError:
            return False
        return True


    @staticmethod
    def can_write(fileName):
        return os.access(fileName, os.W_OK)


    @staticmethod
    def read(fileName):
        result = ''
        with open(fileName, 'r') as fd:
            for line in fd.readlines():
                result += line
        return result


    @staticmethod
    def write(filename, content):
        try:
            with open(filename, 'w') as fd:
                fd.write(content)
        except:
            return False

        return True


    @staticmethod
    def get_lines(fileName):
        with open(fileName, 'r') as fd:
            for line in fd.readlines():
                yield line.replace('\n', '')


    @staticmethod
    def is_dir(fileName):
        return os.path.isdir(fileName)


    @staticmethod
    def is_file(fileName):
        return os.path.isfile(fileName)


    @staticmethod
    def is_directory_empty(directory):
        return len(os.listdir(directory)) == 0


    @staticmethod
    def create_directory(directory):
        try:
            if not FileUtils.exists(directory):
                os.makedirs(directory)
            return True
        except:
            return False


    @staticmethod
    def remove_directory(directory):
        try:
            if FileUtils.is_dir(directory):
                shutil.rmtree(directory, onerror=FileUtils.remove_readonly)
            return True
        except:
            return False


    @staticmethod
    def list_directory(directory):
        try:
            if FileUtils.is_dir(directory):
                return os.listdir(directory)
        except:
            return False


    @staticmethod
    def remove_readonly(func, path, _):
        """Clear the readonly bit and reattempt the removal"""
        os.chmod(path, stat.S_IWRITE)
        func(path)


    @staticmethod
    def size_human(num):
        base = 1024
        for x in ['B ','KB','MB','GB']:
            if num < base and num > -base:
                return "%3.0f%s" % (num, x)
            num /= base
        return "%3.0f %s" % (num, 'TB')


    @staticmethod
    def absolute_path(relative_path):
        try:
            return os.path.abspath(relative_path)
        except:
            return None


    @staticmethod
    def concat_path(path1, path2):
        return path1 + os.path.sep + path2


    @staticmethod
    def check_extension(filename, ext):
        if filename:
            return filename.lower().endswith(ext)
        else:
            return False


    @staticmethod
    def remove_ext(filename):
        return filename[:filename.rfind('.')] if '.' in filename else filename        


    @staticmethod
    def extract_filename(path):
        head, tail = ntpath.split(path)
        return tail or ntpath.basename(head)