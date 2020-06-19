# -*- coding: utf-8 -*-
import time

def get_time_str(t_format='%Y-%m-%d %H:%M:%S'):
    return time.strftime(t_format, time.localtime())