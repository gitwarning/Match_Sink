from share_func import *


def sink_119(line, cv, sink_results, array_sink, sink_appended, sink_cv, pointer_sink, risk_func_sink, point_var):
    if is_array(line, cv) and array_sink:
        print('sink点是数组访问越界：', line)
        sink_results.append(line)
        if not sink_appended:
            sink_cv.append(cv)
            sink_appended = True
        array_sink = False
    if is_pointer(line, cv,point_var) and pointer_sink:
        print('sink点是指针访问越界：', line)
        sink_results.append(line)
        if not sink_appended:
            sink_cv.append(cv)
            sink_appended = True
        pointer_sink = False
    if is_risk_func(line, cv) and risk_func_sink:
        print('sink点是风险函数使用：', line)
        sink_results.append(line)
        if not sink_appended:
            sink_cv.append(cv)
            sink_appended = True
        risk_func_sink = False