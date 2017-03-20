# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import math

def help_div(x,y):
    ''' Handle division by zero '''
    if x == 0 or y == 0:
        return 0
    else:
        return float(x/y)

def calc_mean(numbers):
    return help_div(sum(numbers), float(len(numbers)))

def calc_variance(numbers, threshold, mean=None):
    try:
        if mean == None:
            avg = calc_mean(numbers)
        else:
            avg = mean
        var = float(sum([pow(x-avg,2) for x in numbers]))/float(len(numbers)-1)
        if var == 0:
            return threshold
        return float(sum([pow(x-avg,2) for x in numbers]))/float(len(numbers)-1)
    except ZeroDivisionError:
        return threshold

def calc_stdev(numbers):
    return math.sqrt(calc_variance(numbers))

def calc_stdev_var(variance):
    return math.sqrt(variance)