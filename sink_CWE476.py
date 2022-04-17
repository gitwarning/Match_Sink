from turtle import left
from share_func import *

#该行有对关键变量某个成员的引用
def use_member(line, cv):
    if(line[:len(cv)] == cv):
        left_sign = ''
    else:
        left_sign = ' '
    if(left_sign + cv + ' -> ' in line):
        return True
    elif(left_sign + cv + ' . ' in line):
        return True
    
    return False


def sink_476(line, cv, sink_results, sink_cv, use_null_sink):
    if(('->' in cv) or (' . ' in cv)): #关键变量本身就是某个结构体成员变量
        if(has_cv(line, cv) and use_null_sink):
            sink_results.append(line)
            sink_cv.append(cv)
            use_null_sink = False
        elif(use_member(line, cv) and use_null_sink):
            sink_results.append(line)
            sink_cv.append(cv)
            use_null_sink = False

    if(use_member(line, cv) and use_null_sink):
        sink_results.append(line)
        sink_cv.append(cv)
        use_null_sink = False

    return use_null_sink

