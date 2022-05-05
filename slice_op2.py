## coding:utf-8
from operator import not_
from general_op import *
from Queue import Queue,LifoQueue,PriorityQueue

def get_arguments(db,node_id):
    node_id = int(node_id)
    q = Queue(maxsize=100)
    q.put(node_id)
    nodes = []
    while not q.empty():
        node_id = q.get()
        query_with_var = "g.v(%d).children()" % node_id
        children = db.runGremlinQuery(query_with_var)
        for child in children:                        
            child_type = child['type']
            node_id = child._id
            node_code = child['code']
            if child_type == 'Argument':
                nodes.append(child)
            elif child_type == 'Identifier':
                continue
            else:
                q.put(node_id)
    return nodes

def get_child_type_for_AndOr(db, node_id):
    node_id = int(node_id)
    q = Queue(maxsize=100)
    q.put(node_id)
    # nodeId_type = {}
    node_list = []
    while not q.empty():
        node_id = q.get()
        query_with_var = "g.v(%d).children()" % node_id
        children = db.runGremlinQuery(query_with_var)
        for child in children:                        
            child_type = child['type']
            node_id = child._id
            node_code = child['code']
            if child_type == 'AndExpression' or child_type == 'OrExpression':
                q.put(node_id)
                continue
             
            else:
                node_list.append(child)
                
    return node_list

def get_cv_for_AndOr(db, node):
    node_type = node['type']
    node_code = node['code']
    node_id = int(node._id)
    varlist_in_condition = []

    if node_type == 'RelationalExpression' or node_type == 'EqualityExpression':# (a < 10)/ (a == 10)/ (a != 10)
        operator = node['operator']
        left_part_code  = node_code.split(operator)[0].replace(' ','')
        idents_name = get_all_identifiers_and_ptrArrMem_return_list(db, node_id)
        for ident in idents_name:
            if ident in left_part_code:
                varlist_in_condition.append(ident)

    elif node_type == 'UnaryOp' or node_type == 'IncDecOp': #(!a) / (a --)
        idents_name = get_all_identifiers_and_ptrArrMem_return_list(db, node_id)
        for ident in idents_name:
            varlist_in_condition.append(ident)

    elif node_type == 'CallExpression':
        argument_list = []
        argument_node_list = get_arguments(db, node_id)
        for argument in argument_node_list:
            argument_id = argument._id
            ident_list = get_all_identifiers_and_ptrArrMem_return_list(db, argument_id)
            for ident in ident_list:
                varlist_in_condition.append(ident)

    else:
        varlist_in_condition = condition_value_deliver(db, node_id)
    
    return varlist_in_condition

def condition_value_deliver(db, node_id):
    varlist_in_condition = []
    query_with_var = "g.v(%d).children()" % node_id
    children = db.runGremlinQuery(query_with_var)
    for child in children:
        child_type = child['type']
        child_code = child['code']
        child_id = child._id
        if child_type == 'RelationalExpression' or child_type == 'EqualityExpression':# (a < 10)/ (a == 10)/ (a != 10)
            operator = child['operator']
            left_part_code  = child_code.split(operator)[0].replace(' ','')
            idents_name = get_all_identifiers_and_ptrArrMem_return_list(db, child_id)
            for ident in idents_name:
                if ident in left_part_code:
                    varlist_in_condition.append(ident)

        elif child_type == 'UnaryOp' or child_type == 'IncDecOp': #(!a) / (a --)
            idents_name = get_all_identifiers_and_ptrArrMem_return_list(db, child_id)
            for ident in idents_name:
                varlist_in_condition.append(ident)

        elif child_type == 'CallExpression':
            argument_list = []
            argument_node_list = get_arguments(db, child_id)
            for argument in argument_node_list:
                argument_id = argument._id
                ident_list = get_all_identifiers_and_ptrArrMem_return_list(db, argument_id)
                for ident in ident_list:
                    varlist_in_condition.append(ident)
        # child_type == 'AndExpression' or child_type == 'OrExpression'(a == 0 || b != 0, &&)
        elif child_type == 'AndExpression' or child_type == 'OrExpression':
            node_list = get_child_type_for_AndOr(db, child_id)
            for node in node_list:
                varlist_in_condition = get_cv_for_AndOr(db,node)

        else:
            varlist_in_condition = condition_value_deliver(db, child_id)
    
    return varlist_in_condition

def sub_slice_backwards(startnode, list_node, not_scan_list):
    if startnode['name'] in not_scan_list:
        return list_node, not_scan_list

    else:
        list_node.append(startnode)
        #not_scan_list.append(startnode['name'])
        not_scan_list.add(startnode['name'])
    predecessors = startnode.predecessors()
    startnode_loc = int(startnode['location'].split(':')[0])
    
    if predecessors != []:
        for p_node in predecessors:
            p_node_loc = int(p_node['location'].split(':')[0])
            if(p_node_loc > startnode_loc):
                continue             
            list_node, not_scan_list = sub_slice_backwards(p_node, list_node, not_scan_list)

    return list_node, not_scan_list

#向上切片
def program_slice_backwards(pdg, list_startNode, num):#startNode is a list
    list_all_node = []
    # not_scan_list = []
    not_scan_list = set()
    for startNode in list_startNode:
        list_node = [startNode]
        # not_scan_list.append(startNode['name'])
        not_scan_list.add(startNode['name'])
        predecessors = startNode.predecessors()
        startNode_loc = int(startNode['location'].split(':')[0])

        if predecessors != []:
            for p_node in predecessors:
                p_node_loc = int(p_node['location'].split(':')[0])
                if(p_node_loc > startNode_loc):
                    continue
                list_node, not_scan_list = sub_slice_backwards(p_node, list_node, not_scan_list)

        list_all_node += list_node
       
        #Add function define line
        if startNode['functionId'] in not_scan_list:
            continue
        for node in pdg.vs:
            if node['name'] == startNode['functionId']:
                list_all_node.append(node)
                not_scan_list.append(node['name'])
                break
        
    # print("list_all_node:", list_all_node)
    list_ordered_node = sortedNodesByLoc(list_all_node)

    # _list_re = []
    # a = 0
    # while a < len(list_ordered_node):
    #     if list_ordered_node[a]['name'] not in _list_re:
    #         _list_re.append(list_ordered_node[a]['name'])
    #         a += 1
    #     else:
    #         del list_ordered_node[a]
    final_list_node = []
    for node in list_ordered_node:
        new_node = [node, num]
        final_list_node.append(new_node)
    # return list_ordered_node
    return final_list_node


def sub_slice_forward(startnode, list_node, not_scan_list):
    if startnode['name'] in not_scan_list:
        return list_node, not_scan_list

    else:
        list_node.append(startnode)
        #not_scan_list.append(startnode['name'])
        not_scan_list.add(startnode['name'])
    successors = startnode.successors()
    startnode_loc = int(startnode['location'].split(':')[0])
    
    if successors != []:
        for p_node in successors:
            p_node_loc = int(p_node['location'].split(':')[0])
            if(p_node_loc < startnode_loc):
                continue   
            list_node, not_scan_list = sub_slice_forward(p_node, list_node, not_scan_list)

    return list_node, not_scan_list

#向下切片
def program_slice_forward(pdg, list_startNode, num):#startNode is a list of parameters, only consider data dependency
    pdg = del_ctrl_edge(pdg)
            
    list_all_node = []
    # not_scan_list = []
    not_scan_list = set()
    for startNode in list_startNode:
        list_node = [startNode]
        # not_scan_list.append(startNode['name'])
        not_scan_list.add(startNode['name'])
        successors = startNode.successors()
        startNode_loc = int(startNode['location'].split(':')[0])
        
        if successors != []:
            for p_node in successors:
                p_node_loc = int(p_node['location'].split(':')[0])
                if(p_node_loc < startNode_loc):
                    continue
                list_node, not_scan_list = sub_slice_forward(p_node, list_node, not_scan_list)

        list_all_node += list_node

    list_ordered_node = sortedNodesByLoc(list_all_node)

    # a = 0
    # _list_re = []
    # while a < len(list_ordered_node):
    #     if list_ordered_node[a]['name'] not in _list_re:
    #         _list_re.append(list_ordered_node[a]['name'])
    #         a += 1
    #     else:
    #         del list_ordered_node[a]

    final_list_node = []
    for node in list_ordered_node:
        new_node = [node, num]
        final_list_node.append(new_node)
    # return list_ordered_node
    return final_list_node

def get_all_identifiers_and_ptrArrMem_return_list(db, node_id):
    node_id = int(node_id)
    identifiers = []
    query_with_var = "g.v(%d).children()" % node_id
    children = db.runGremlinQuery(query_with_var)
    for child in children:
        node_id = child._id
        node_type = child['type']
        node_code = child['code']
        if node_type == "Identifier":
            identifiers.append(node_code)               
        else:
            if node_type == "PtrMemberAccess" or node_type == "ArrayIndexing" or node_type == 'MemberAccess':
                node_code.replace(" ","")
                identifiers.append(node_code)            
            q = Queue(maxsize=100)
            q.put(node_id)
            while not q.empty():
                node_id = q.get()
                query_with_var = "g.v(%d).children()" % node_id
                children = db.runGremlinQuery(query_with_var)
                for child in children:                        
                    child_type = child['type']
                    child_id = child._id
                    child_code = child['code'].replace(' ','')
                    if child_type == 'Identifier':
                        identifiers.append(child_code)
                    else:
                        if child_type == "PtrMemberAccess" or child_type == "ArrayIndexing" or child_type == 'MemberAccess':
                            identifiers.append(child_code)
                        q.put(child_id)


    identifiers = list(set(identifiers))
    return identifiers

def select_successors_for_condition(db, startnode):
    successors_all = startnode.successors()
    successors_all = list(set(successors_all))
    print('\n\t--------- succs of ',startnode['code'],'\t',startnode['location'])
    for suc in successors_all:
        print('\tall_succs:\t',suc['code'])

    condition_id = int(startnode['name'])
    startnode_line = startnode['location'].split(":")[0]
    successors_temp = []
    successors = []
    vars_in_cond_stmt = []

    query_with_var = "g.v(%d).parents()" % condition_id
    parents = db.runGremlinQuery(query_with_var)

    for res in parents:
        if res['type'] == 'ForStatement':
            forstmt_id = res._id
            var_in_forstmt = []

            query_with_var = "g.v(%d).children()" % forstmt_id
            children = db.runGremlinQuery(query_with_var)

            for child in children:
                child_type = child['type']
                child_id = child._id
                if child_type == 'ForInit' or child_type == "IncDecOp":
                    idents_in_forInit = []
                    idents_in_forInit = get_all_identifiers_and_ptrArrMem_return_list(db, child_id)
                    if idents_in_forInit != []:
                        for ident in idents_in_forInit:
                            var_in_forstmt.append(ident)
                
                elif child_type == 'Condition':
                    
                    var_in_condition = condition_value_deliver(db, child_id)
                    for var in var_in_condition:
                        var_in_forstmt.append(var)

                else:
                    continue
            
            vars_in_cond_stmt = list(set(var_in_forstmt))
        
        elif res['type'] == 'IfStatement':
            var_in_ifstmt = []
            query_with_var = "g.v(%d).children()" % res._id
            if_stmt_child = db.runGremlinQuery(query_with_var)
            for child in if_stmt_child:
                child_id = child._id
                child_type = child['type']
                varlist_in_condition = []
                if child_type == 'Condition':
                    var_in_condition = condition_value_deliver(db, child_id)
                    for var in var_in_condition:
                        var_in_ifstmt.append(var)
                break
            
            vars_in_cond_stmt = list(set(var_in_ifstmt))

        elif res['type'] == 'WhileStatement':
            var_in_whilestmt = []
            query_with_var = "g.v(%d).children()" % res._id
            while_stmt_child = db.runGremlinQuery(query_with_var)
            for child in while_stmt_child:
                child_id = child._id
                child_type = child['type']
                varlist_in_condition = []
                if child_type == 'Condition':
                    var_in_condition = condition_value_deliver(db, child_id)
                    for var in var_in_condition:
                        var_in_whilestmt.append(var)
                break
            
            vars_in_cond_stmt = list(set(var_in_whilestmt))

        elif res['type'] == 'SwitchStatement':
            return []              
                        
        else:
            successors_temp += successors_all

    for succ in successors_all:
        succ_id = succ['name']
        idents_in_succ = get_all_identifiers_and_ptrArrMem_return_list(db, succ_id)
        if vars_in_cond_stmt != []:
            for var in vars_in_cond_stmt:
                for ident in idents_in_succ:
                    if ident == var:
                        successors_temp.append(succ)
                        break
                    
    successors_temp = list(set(successors_temp))
    for node in successors_temp:
        line = node['location'].split(":")[0]
        if line > startnode_line:
            successors.append(node)

    if successors == []:
        print('-----------------------------------------------------------------------------------------------------------------------------------------')
        print("startnode: ",startnode['location'],"   HAS NO SUCCESSORS!","     startnode_id: ",condition_id)
        print('-----------------------------------------------------------------------------------------------------------------------------------------')
        return []

    else:
        for suc in successors:
            print('\tselected_succs:\t',suc['code'])
        return successors

#(用于向上的切片也需要跨函数的情况,该版本不需要)
def process_cross_func(to_scan_list, testID, slicetype, list_result_node, not_scan_func_list):
    if to_scan_list == []:
        return list_result_node, not_scan_func_list

    for node in to_scan_list:
        if node['name'] in not_scan_func_list:
            continue

        ret = isNewOrDelOp(node, testID)
        if ret:
            funcname = ret
            pdg = getFuncPDGByNameAndtestID(funcname, testID)              

            
            if pdg == False:
                not_scan_func_list.append(node['name'])
                continue

            else:
                result_list = sortedNodesByLoc(pdg.vs)

                not_scan_func_list.append(node['name'])

                index = 0
                for result_node in list_result_node:
                    if result_node['name'] == node['name']:
                        break
                    else:
                        index += 1

                list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                list_result_node, not_scan_func_list = process_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list)


        else:          
            ret = isFuncCall(node)#if funccall ,if so ,return funcnamelist 如果是一个函数调用语句，则返回该语句调用的函数名
            if ret:

                for funcname in ret:
                    if funcname.find('->') != -1:
                        real_funcname = funcname.split('->')[-1].strip()
                        objectname = funcname.split('->')[0].strip()

                        funcID = node['functionId']
                        src_pdg = getFuncPDGByfuncIDAndtestID(funcID, testID)
                        if src_pdg == False:
                            continue
                            
                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname
                        pdg = getFuncPDGByNameAndtestID_noctrl(funcname, testID)


                    elif funcname.find('.') != -1:
                        real_funcname = funcname.split('.')[-1].strip()
                        objectname = funcname.split('.')[0].strip()

                        funcID = node['functionId']
                        # src_pdg = getFuncPDGByNameAndtestID_noctrl(funcID, testID)
                        src_pdg = getFuncPDGByfuncIDAndtestID(funcID, testID)
                        if src_pdg == False:
                            continue
                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)

                    else:
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)

                    if pdg == False:
                        not_scan_func_list.append(node['name'])
                        continue

                    else:
                        if slicetype == 0:
                            ret_node = []
                            for vertex in pdg.vs:
                                if vertex['type'] == 'ReturnStatement':#找到return语句的变量
                                    ret_node.append(vertex)

                            result_list = program_slice_backwards(pdg, ret_node)#从return语句开始在该函数中向上切
                            not_scan_func_list.append(node['name'])

                            index = 0
                            for result_node in list_result_node:
                                if result_node['name'] == node['name']:
                                    break
                                else:
                                    index += 1
                                
                            list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                            list_result_node, not_scan_func_list = process_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list)

                        elif slicetype == 1:
                            param_node = []
                            FuncEntryNode = False
                            for vertex in pdg.vs:
                                if vertex['type'] == 'Parameter':#函数定义处的参数
                                    param_node.append(vertex)#从函数参数变量开始向下切
                                elif vertex['type'] == 'Function':
                                    FuncEntryNode = vertex

                            if param_node != []:
                                result_list = program_slice_forward(pdg, param_node)
                            else:
                                result_list = sortedNodesByLoc(pdg.vs)

                            not_scan_func_list.append(node['name'])
                            index = 0

                            for result_node in list_result_node:
                                if result_node['name'] == node['name']:
                                    break
                                else:
                                    index += 1

                            if FuncEntryNode != False:
                                result_list.insert(0, FuncEntryNode)
                                
                            list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                            list_result_node, not_scan_func_list = process_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list)


    return list_result_node, not_scan_func_list

#这个函数好像只会向上找3层(用于向上的切片也需要跨函数的情况,该版本不需要)
def process_crossfuncs_back_byfirstnode(list_tuple_results_back, testID, i, not_scan_func_list):
    #is not a good way in time, list_tuple_results_back=[(results_back, itertimes)]
    while i < len(list_tuple_results_back):
        iter_time = list_tuple_results_back[i][1]
        if iter_time == 3 or iter_time == -1:#allow cross 3 funcs:
            i += 1
            continue

        else:
            list_node = list_tuple_results_back[i][0]

            if len(list_node) == 1:
                i += 1
                continue

            if list_node[1]['type'] == 'Parameter':#如果开头是函数定义的开头
                func_name = list_node[0]['name']#获取该函数的id
                path = os.path.join('dict_call2cfgNodeID_funcID', testID, 'dict.pkl')

                if not os.path.exists(path):
                    i += 1
                    continue

                fin = open(path, 'rb')
                _dict = pickle.load(fin)
                fin.close()
                
                if func_name not in _dict.keys():
                    list_tuple_results_back[i][1] = -1
                    i += 1
                    continue

                else:                
                    list_cfgNodeID = _dict[func_name]#获取调用其的函数
                    dict_func_pdg = getFuncPDGBynodeIDAndtestID(list_cfgNodeID, testID)#获取pdg图
                    iter_time += 1 #函数层数+1
                    _new_list = []
                    for item in dict_func_pdg.items():
                        targetPDG = item[1]
                        startnode = []
                        for n in targetPDG.vs:
                            if n['name'] == item[0]:#is id
                                startnode = [n]
                                break
                        
                        if startnode == []:
                            continue
                        if startnode[0]['name'] in not_scan_func_list:
                            continue
                        ret_list = program_slice_backwards(targetPDG, startnode)#在新函数中往上切
                        not_scan_func_list.append(startnode[0]['name'])#将这一句调用(漏洞函数的)语句加入

                        ret_list = ret_list + list_node #因为是向前切，所以要把list_node连到后面
                        _new_list.append([ret_list, iter_time])

                    if _new_list != []:
                        del list_tuple_results_back[i] #删除原来的，将已经加入ret_list的变成list_tuple_results_back
                        list_tuple_results_back = list_tuple_results_back + _new_list
                        list_tuple_results_back, not_scan_func_list = process_crossfuncs_back_byfirstnode(list_tuple_results_back, testID, i, not_scan_func_list)
                    else:
                        list_tuple_results_back[i][1] = -1
                        i += 1
                        continue
                        

            else:
                funcname = list_node[0]['code']
                if funcname.find("::") > -1:

                    path = os.path.join('dict_call2cfgNodeID_funcID', testID, 'dict.pkl')#get funname and it call place
                    if not os.path.exists(path):
	                    i += 1
	                    continue
                    fin = open(path, 'rb')
                    _dict = pickle.load(fin)
                    fin.close()



                    func_name = list_node[0]['name']
                    # print _dict.keys()
                    if func_name not in _dict.keys():
                        list_tuple_results_back[i][1] = -1
                        i += 1
                        continue

                    else:               
                        list_cfgNodeID = _dict[func_name]
                        dict_func_pdg = getFuncPDGBynodeIDAndtestID(list_cfgNodeID, testID)
                        
                        iter_time += 1
                        _new_list = []
                        for item in dict_func_pdg.items():
                            targetPDG = item[1]
                            startnode = []
                            for n in targetPDG.vs:
                                if n['name'] == item[0]:#is id
                                    startnode = [n]
                                    break
                            if startnode == []:
                                continue 
                            if startnode[0]['name'] in not_scan_func_list:
                                continue   
                            ret_list = program_slice_backwards(targetPDG, startnode)
                            not_scan_func_list.append(startnode[0]['name'])
                            
                            
                            ret_list = ret_list + list_node
                            _new_list.append([ret_list, iter_time])

                        # print "_new_list: ",_new_list
                        if _new_list != []:
                            del list_tuple_results_back[i]
                            list_tuple_results_back = list_tuple_results_back + _new_list
                            list_tuple_results_back, not_scan_func_list = process_crossfuncs_back_byfirstnode(list_tuple_results_back, testID, i, not_scan_func_list)

                        else:
                            list_tuple_results_back[i][1] = -1
                            i += 1
                            continue

                else:
                    i += 1
                    continue
                   
    return list_tuple_results_back, not_scan_func_list


def backward_to_decl(db, startnode, variable_name):
    #tarck backward dataflow to identifierDeclaration of the cirital variable 
    identifierDecl, variable_name = select_predecessors(db,startnode, variable_name)
    if identifierDecl == []:
        return [],[],variable_name
    startnode_new = identifierDecl[0]
    flag, successors = select_successors(db, startnode_new, variable_name)
    return identifierDecl, successors, variable_name

def select_predecessors(db, startnode, variable_name):
    varias = []
    identifierDecl = []
    predecessors = startnode.predecessors()

    query_with_var = "g.v(%d).parents().parents().parents()" % int(startnode['name'])
    parents = db.runGremlinQuery(query_with_var)

    if len(parents) == 1 and parents[0]['type'] == 'ForStatement':
        identifs = []
        query_with_var = "g.v(%d).children().children().children()" % int(parents[0]._id)
        identifiers = db.runGremlinQuery(query_with_var)
        for ident in identifiers:
            if ident['type'] == 'Identifier':
                identifs.append(ident['code'])

        for identi in identifs:
            if variable_name == identi:
                query_with_var = "g.v(%d).children()" % int(parents[0]._id)
                chilren = db.runGremlinQuery(query_with_var)
                for pre in predecessors:
                    for child in chilren:
                        if int(pre['name']) == child._id and pre['type'] == 'Condition':
                            return [pre],variable_name

    if "*" in variable_name:
        variable_name = variable_name.split("*")[-1]

    for p_node in predecessors:
        node_type = p_node['type']
        code = p_node['code']
        node_id = int(p_node['name'])
        idents_in_pre = get_all_identifiers_and_ptrArrMem_return_list(db, node_id)
        if node_type == 'IdentifierDeclStatement' or node_type == 'Parameter':
            if variable_name in idents_in_pre:
                identifierDecl.append(p_node)
    if identifierDecl == []:
        class_name = ''
        if "->" in variable_name:
            class_name = variable_name.split("->")[0]
            for p_node in predecessors:
                node_type = p_node['type']
                code = p_node['code']
                if node_type == 'IdentifierDeclStatement' or node_type == 'Parameter': 
                    if class_name in code:
                        identifierDecl.append(p_node)
                        variable_name = class_name
                        break

        elif "." in variable_name:
            class_name = variable_name.split(".")[0]
            for p_node in predecessors:
                node_type = p_node['type']
                code = p_node['code']
                if node_type == 'IdentifierDeclStatement' or node_type == 'Parameter':
                    if class_name in code:
                        identifierDecl.append(p_node)
                        variable_name = class_name
                        break

        else:
            print("NO PREDESSORS???")
            return [], variable_name

    if len(identifierDecl) != 1:
        print("The number of identifierdel ERRORS!!!")
    return identifierDecl, variable_name

def select_successors(db, startnode, variable_name):
    flag = 0
    #if the identifierDeclaration statement declares more than one variables
    #the successors of this node would include all variables' successors, so it has to be filtered
    successors_all = startnode.successors()
    successors_all = list(set(successors_all))
    print('\n\t------------- succs of ',startnode['code'],'\t',startnode['location'], '\tcv: '),  variable_name
    if successors_all == []:
        return flag, []
    for suc in successors_all:
        print('\tall_succs:\t',suc['code'], '\t', suc['location'])
    startnode_type = startnode["type"]
    startnode_line = startnode['location'].split(":")[0]
    startnode_code = startnode['code']
    successors_temp = []
    successors = []
    
    #declaration has wrong station that include more than one variable's successors
    #Startnode为identifierDeclStatement类型，并且该行定义了多个变量，e.g., int a,b,c 
    if startnode_type == "IdentifierDeclStatement" and ',' in startnode_code:
        # filter successors that are not related to the ciritical variable
        for succ_node in successors_all:
            succ_id = int(succ_node['name'])
            
            idents_in_succ = get_all_identifiers_and_ptrArrMem_return_list(db, succ_id)
            if idents_in_succ == []:
                successors_temp.append(succ_node)
            else:    
                for ident in idents_in_succ:
                    if ident == variable_name:
                        successors_temp.append(succ_node)
    elif startnode_type == "Condition":
        successors_temp = select_successors_for_condition(db, startnode)
        
    else:
        for succ_node in successors_all:
            succ_id = int(succ_node['name'])
            idents_in_succ = get_all_identifiers_and_ptrArrMem_return_list(db, succ_id)
            if variable_name in idents_in_succ:
                successors_temp.append(succ_node)

    for node in successors_temp:
        line = node['location'].split(":")[0]
        if line > startnode_line:
            successors.append(node)

    for suc in successors:
        print('\tselected_succs:\t',suc['code'], '\t', suc['location'])

    if successors == {}:
        flag = 1
        print("startnode: ",startnode['location'],"   HAS NO SUCCESSORS!")
        return flag,[]

    else:
        flag = 0    
        return flag, successors

#获取漏洞函数return之后的切片
def process_return_func(all_results_list, list_start_node, testID, layer, vulfunc, cnt, current_layer): #startnode是漏洞函数中的关注点

    if(layer <= 0):
        return []

    list_ret_slice = []
    func_id = list_start_node['functionId'] #获取该漏洞函数的id
    #func_name = node['code'] #获取该漏洞函数的名字
    path = os.path.join('dict_call2cfgNodeID_funcID', testID, 'dict.pkl')

    if(not os.path.exists(path)):
        print("can't find func_call in _dict.")
        return []
    fin = open(path, 'rb')
    _dict = pickle.load(fin)
    fin.close()

    if(func_id not in _dict.keys()):
        print('func_id is not in _dict.')
        return []
    else:
        cfgNodeID = _dict[func_id] #获取调用它的函数
        func_pdg = getFuncPDGBynodeIDAndtestID(cfgNodeID, testID)#获取pdg图
        print(len(func_pdg.items()), "layer:", layer)
        #fdscgfre
        #找到调用漏洞函数的语句
        for item in func_pdg.items():#可能存在多个调用的地方
            targetPDG = item[1]
            print(item)
            startnode = []
            for n in targetPDG.vs:
                if(n['name'] == item[0]):
                    list_start_node = n #将下次循环的startnode换成新的函数
                    new_vulfunc = isFuncCall(list_start_node)[0]
                    startnode = [n] #startnode获取的是调用漏洞函数的语句
                    break
            if(startnode == []):
                return []
            
            #从该语句向下切片(只考虑数据依赖)
            ret_for = program_slice_forward(targetPDG, startnode, current_layer + 1)

            #list_resut_back = return_cross_func(ret_for, testID, 0, ret_for, [], cnt)
            #看这些向下的切片里面有没有跨函数的
            list_result_for, not_scan = return_cross_func(ret_for, testID, 1, ret_for, startnode, new_vulfunc, cnt, current_layer + 1)
            print('list_result_for:')
            print(list_result_for)
            
            #获取return之后的切片,这里传进去的list_ret_slice似乎一直都会是[]
            all_result = process_return_func(list_ret_slice, list_start_node, testID, layer - 1, new_vulfunc, cnt, current_layer + 1)
            #list_ret_slice.append(list_result_for + all_result)
            print('all_result:')
            print(all_result)
            
            if(all_result == []):
                list_ret_slice.append(list_result_for)
            else:                
                for ab in all_result:
                    list_ret_slice.append(list_result_for + ab)
                       
          
    return list_ret_slice

# 执行向下跨函数的作用
# current_layer:当前是针对漏洞函数来说的第几层跨函数
def return_cross_func(to_scan_list, testID, slicetype, list_result_node, not_scan_func_list, vulfunc, cnt, current_layer):
    if(cnt <= 0):
        return list_result_node, not_scan_func_list

    for node in to_scan_list:
        node = node[0]
        num = cnt
        # if node['name'] in not_scan_func_list:
        #     continue

        ret = isNewOrDelOp(node, testID)
        if ret:
            funcname = ret
            pdg = getFuncPDGByNameAndtestID(funcname, testID)
            #cnt -= 1
            num -= 1

            if pdg == False:
                not_scan_func_list.append(node['name'])
                continue

            else:
                # result_list = sortedNodesByLoc(pdg.vs)
                result_list_tmp = sortedNodesByLoc(pdg.vs)
                for rl in result_list_tmp:
                    new_rl = [rl, current_layer + 1]
                    result_list.append(new_rl)

                not_scan_func_list.append(node['name'])

                index = 0
                for result_node in list_result_node:
                    if result_node[0]['name'] == node[0]['name']:
                        break
                    else:
                        index += 1

                list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                list_result_node, not_scan_func_list = return_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list, cnt, current_layer + 1)


        else:          
            ret = isFuncCall(node)#if funccall ,if so ,return funcnamelist
            if ret:
                
                for funcname in ret:
                    if(funcname == vulfunc):
                        continue
                    if funcname.find('->') != -1:
                        real_funcname = funcname.split('->')[-1].strip()
                        objectname = funcname.split('->')[0].strip()

                        funcID = node['functionId']
                        src_pdg = getFuncPDGByfuncIDAndtestID(funcID, testID)
                        if src_pdg == False:
                            continue
                            
                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:#找到创建该结构体对象的语句
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname #会找到真正的函数的,所以可以处理结构体函数
                        pdg = getFuncPDGByNameAndtestID_noctrl(funcname, testID)
                        #cnt -= 1 #已经往下找了一层了
                        num -= 1


                    elif funcname.find('.') != -1:
                        real_funcname = funcname.split('.')[-1].strip()
                        objectname = funcname.split('.')[0].strip()

                        funcID = node['functionId']
                        # src_pdg = getFuncPDGByNameAndtestID_noctrl(funcID, testID)
                        src_pdg = getFuncPDGByfuncIDAndtestID(funcID, testID)
                        if src_pdg == False:
                            continue
                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)
                        #cnt -= 1 #已经往下找了一层了
                        num -= 1

                    else:
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)#获取的是该语句调用的函数的pdg图
                        #cnt -= 1 #已经往下找了一层了
                        num -= 1

                    if pdg == False:
                        not_scan_func_list.append(node['name'])
                        continue

                    else:
                        # if slicetype == 0:
                        #     ret_node = []
                        #     for vertex in pdg.vs:
                        #         if vertex['type'] == 'ReturnStatement':
                        #             ret_node.append(vertex)

                        #     result_list = program_slice_backwards(pdg, ret_node)
                        #     not_scan_func_list.append(node['name'])

                        #     index = 0
                        #     for result_node in list_result_node:
                        #         if result_node['name'] == node['name']:
                        #             break
                        #         else:
                        #             index += 1
                                
                        #     list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                        #     list_result_node, not_scan_func_list = return_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list, cnt)

                        # elif slicetype == 1:
                        if slicetype == 1:
                            param_node = []
                            FuncEntryNode = False
                            for vertex in pdg.vs:
                                if vertex['type'] == 'Parameter':
                                    param_node.append(vertex)
                                elif vertex['type'] == 'Function':
                                    FuncEntryNode = vertex

                            if param_node != []:
                                result_list = program_slice_forward(pdg, param_node, current_layer + 1) # 向下调用了一层，current_ayer+1
                            else:
                                result_list_tmp = sortedNodesByLoc(pdg.vs) # 所调用的函数没有参数的情况
                                for rl in result_list_tmp:
                                    new_rl = [rl, current_layer + 1]
                                    result_list.append(new_rl)


                            not_scan_func_list.append(node['name'])
                            index = 0

                            for result_node in list_result_node:
                                if result_node[0]['name'] == node['name']:
                                    break
                                else:
                                    index += 1

                            if FuncEntryNode != False:
                                result_list.insert(0, [FuncEntryNode, current_layer + 1])
                                
                            list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                            list_result_node, not_scan_func_list = return_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list, vulfunc, num, current_layer + 1)#我完全懂了


    return list_result_node, not_scan_func_list
