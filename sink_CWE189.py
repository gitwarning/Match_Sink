from share_func import *
from sink_CWE369 import is_divisin


def is_risk_func_189(line ,cv):
    if not has_cv(cv, line):  # ar -> gpe . en = g_malloc0 ( len / 2 ); 避免这种情况匹配不到
        return False
    funcnames = get_funcname(line)
    if(funcnames == []):
        return False
    for func in funcnames:
        if ('memcpy' in func):  # 之后换成正则表达式应该会更好
            return True
        elif ('alloc' in func):
            return True
        elif ('memset' in func):
            return True
        elif ('bytestream2_get_buffer' in func):
            return True
        elif ('get_bits' in func):
            return True
        elif ('put_bits' in func):
            return True
        elif ('copy' in func):
            return True
        elif ('recv' in func and 'recv ->' not in func):
            return True
        elif('vfs_write' in func):
            return True
        elif 'AcquireVirtualMemory' in func:
            return True
        elif 'TT_NEXT_U' in func: #针对freetype2软件中的TT_NEXT_ULONG/INT(...)宏定义
            return True
        elif 'FT_MEM_SET' in func: #freetype2软件中该函数经过两层宏定义变成memset
            return True
        elif 'do_div' in func: #做除法的函数(宏定义)
            return True
    
    return False

def sink_189(line, cv, sink_results, array_sink, sink_cv, pointer_sink, risk_func_sink, calculation_sink, point_var, division_sink ):
    if is_array(line, cv) and array_sink:
        print('sink点是数组访问越界：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        array_sink = False
    if is_pointer(line, cv, point_var) and pointer_sink:
        print('sink点是指针访问越界：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        pointer_sink = False
    if is_risk_func_189(line, cv) and risk_func_sink:
        print('sink点是风险函数使用：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        risk_func_sink = False
    if is_calculation(line, cv) and calculation_sink:
        print('此行是整数运算导致的整数溢出类型：', line)  # 整数溢出后还会造成影响的
        sink_results.append(line)
        calculation_sink = False
    if is_divisin(line, cv) and division_sink:
        print('此行是除以零的整数错误：', line)  # 整数溢出后还会造成影响的
        sink_results.append(line)
        division_sink = False
    return array_sink, pointer_sink, risk_func_sink, calculation_sink, division_sink
