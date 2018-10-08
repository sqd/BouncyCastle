# -*- coding: utf-8 -*-

import logging

def getLogger(name):
    logging.basicConfig(format="%(asctime)s %(message)s", level=logging.DEBUG)
    logger = logging.getLogger(name)

    return logger
