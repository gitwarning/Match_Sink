from share_func import has_cv


def is_path(line, cv):

    if not has_cv(cv, line):  # ar -> gpe . en = g_malloc0 ( len / 2 ); 避免这种情况匹配不到
        return False

    if ('open' in line):
        return True
    elif ('read' in line):
        return True
    elif ('mkdir' in line):
        return True
    elif ('path_copy' in line):
        return True
    elif ('append' in line):
        return True
    elif ('setProperty' in line):
        return True
    else:
        return False


def sink_22(line, cv, sink_results, path_sink, sink_cv):
    if is_path(line, cv) and path_sink:
        print('sink点是调用路径访问的函数：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        path_sink = False
    return path_sink
