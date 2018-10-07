# -*- coding: utf-8 -*-
from typing import Generic


class Ref(Generic[T]):
    """
    Pass statis values (str, int, etc) by reference.
    """
    def __init__(self, v: T):
        self.v: T = v
