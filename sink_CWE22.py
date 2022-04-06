def is_path(line, cv):
    if (' ' + cv + ' ' not in line):
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


def sink_22(line, cv, sink_results, path_sink, sink_cv):
    if is_path(line, cv) and path_sink:
        print('sink点是调用路径访问的函数：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        path_sink = False