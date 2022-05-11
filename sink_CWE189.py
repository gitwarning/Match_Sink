from share_func import *

def is_risk_func_189(line ,cv):
    if not has_cv(cv, line):  # ar -> gpe . en = g_malloc0 ( len / 2 ); 避免这种情况匹配不到
        return False
    if ('memcpy' in line):  # 之后换成正则表达式应该会更好
        return True
    elif ('alloc' in line):
        return True
    elif ('memset' in line):
        return True
    elif ('bytestream2_get_buffer' in line):
        return True
    elif ('get_bits' in line):
        return True
    elif ('put_bits' in line):
        return True
    elif ('copy' in line):
        return True
    elif ('recv' in line and 'recv ->' not in line):
        return True
    elif 'AcquireVirtualMemory' in line:
        return True
    elif 'TT_NEXT_U' in line: #针对freetype2软件中的TT_NEXT_ULONG/INT(...)宏定义
        return True
    elif 'FT_MEM_SET' in line: #freetype2软件中该函数经过两层宏定义变成memset
        return True
    else:
        return False

def sink_189(line, cv, sink_results, array_sink, sink_cv, pointer_sink, risk_func_sink, calculation_sink, point_var ):
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
    return array_sink, pointer_sink, risk_func_sink, calculation_sink
