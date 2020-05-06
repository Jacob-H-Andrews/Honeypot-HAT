import re
import datetime as dt
import sys
import networkx as nx
from pylab import rcParams, matplotlib
import seaborn as sb
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.collections import PolyCollection

################################################
########## ACCESS LOG & FINDING NODES ##########
################################################
def accessLog():
    #NGINX Ubuntu access log directory
    #f = open("/var/log/nginx/access.log", "r")
    f = open("server_logs/server_access.log", "r")
    return f

# Remove unecessary data from log
def delFavicon(log):
    log_lines = log.readlines()
    with open("server_logs/processed_server_access.log", "w") as f:
        for line in log_lines:
            if "favicon" not in line:
                f.write(line)
    f = open("server_logs/processed_server_access.log", "r")
    return f

def scanForNodeAction(log):
    events = []
    n_events = 0
    n_nodes = 0
    n_actions = 0
    all_node_action = {} #dict
    sessions_dt = []
    sessions_t = []
    
    # Add network events to a list
    for event in log:
        events.append(event)    
        n_events += 1

    # Finds nodes
    for event in range(n_events):
        if "GET / HTTP/1.1" in events[event]:
            session_date_time = re.search('\\[(.+?) \\+', events[event]).group(1)
            session_time = re.search('\\:(.+?) \\+', events[event]).group(1)
            sessions_dt.append(session_date_time)
            sessions_t.append(session_time)
            #print("Node Found at line: ", event)
            node_locale = event
            node_action_start = node_locale+1
            
            # If node found, find actions
            node_actions = []
            for i in range(node_action_start, n_events):
                if "GET / HTTP/1.1" not in events[i]:
                    #print("Node action at line: ", i)
                    n_actions += 1
                    node_actions.append(events[i])
                else:
                    # Found another node
                    break
                
            # Appends each nodes' actions to a dictionary
            # key = (node) 1st/2nd/3rd..node found, value = node_actions
            node = n_nodes
            all_node_action[node] = node_actions
            n_nodes += 1
    
    # Overview
    print("\nSCAN COMPLETE")
    print("Nodes Found: ",n_nodes)
    print("Actions Found: ",n_actions,"\n\n\n")

    if all_node_action == {}:
        print("NO RELEVANT DATA FOUND")
        print("LOG ANALYSIS SHUTTING DOWN...")
        sys.exit()

    return all_node_action, n_nodes, n_actions, sessions_dt, sessions_t

#----------------------------------------------#



################################################
############## NODE ACTION & GRAPHS ############
################################################

def nodeActionBreakdown(all_node_action, node, session_start_dt, session_start_t):
    actions = len(all_node_action[node])
    all_pages_visited = []
    action_date_times = []
    action_times = []
    instance_time_on_pages = []
    total_time_on_pages = {}
    zero = []
    timeline_data = []

    # Adds index to the start of the travel path    
    all_pages_visited.insert(0,'index')
    
    # Add session start times to action times list
    action_date_times.append(session_start_dt)
    action_times.append(session_start_t)

    for action in range(actions):
        event = all_node_action[node][action]
        
        # All pages visited
        try:
            page_found = re.search('GET /(.+?).html', event).group(1)
            all_pages_visited.append(page_found)
        except AttributeError:
            page_found = ''
        
        # Date & time of actions
        try:
            action_dt_found = re.search('\\[(.+?) \\+', event).group(1)
            action_t_found = re.search('\\:(.+?) \\+', event).group(1)
            action_date_times.append(action_dt_found)
            action_times.append(action_t_found)
        except AttributeError:
            action_dt_found = ''
            action_t_found = ''

    # This is essential for acumulating the total time spent on each page
    for i in range(len(all_pages_visited)):
        zero.append(0)
    total_time_on_pages = dict(zip(all_pages_visited,zero))

    # Time spent on each page
    n_times = len(action_times)
    for x_time in range(n_times):
        current_page = all_pages_visited[x_time]
        if x_time+1 == n_times & n_times != 1:
            instance_time_on_pages.append(current_page)
            instance_time_on_pages.append("N/A")
            
            existing_time = total_time_on_pages.get(current_page)
            total_time_on_pages.update({current_page: existing_time}) #+'+'
            break;
        elif n_times == 1:
            break;
        else:
            page_x = action_times[x_time]
            page_y = action_times[x_time+1]
            page_x_t = dt.datetime.strptime(page_x, '%H:%M:%S')
            page_y_t = dt.datetime.strptime(page_y, '%H:%M:%S')
            total_t_page_x = page_y_t - page_x_t
            total_seconds = abs(total_t_page_x.total_seconds())

            # Used for timeline of node
            timeline_data.append((page_x_t,page_y_t,current_page))
            
            # Time spent on each page as individual instances
            instance_time_on_pages.append(current_page)
            instance_time_on_pages.append(total_seconds)
            
            # Total time on each page
            existing_time = total_time_on_pages.get(current_page)
            if existing_time != 0:
                new_time = existing_time + total_seconds
                total_time_on_pages.update({current_page: new_time})
            else:
                total_time_on_pages.update({current_page: total_seconds})

    
    #If the website was accessed with 0 movement       
    if len(all_pages_visited) == 1:
        # Adds index to the start of the travel path    
        #pages_visited.insert(0,'index')
        print("\nNODE",node+1,"ANALYSIS COMPLETE")     
        print("ZERO MOVEMENT")
        print("Session start:",session_start_dt)
        print("Pages visited:",all_pages_visited)
        return all_pages_visited, timeline_data, total_time_on_pages
    else:
        #Session end
        try:
            session_end = re.search('\\[(.+?) \\+', all_node_action[node][actions-1]).group(1)
        except AttributeError:
            session_end = ''
        
        #Total session time
        try:
            found_end = re.search('\\:(.+?) \\+', all_node_action[node][actions-1]).group(1)
            t1 = dt.datetime.strptime(session_start_t, '%H:%M:%S')
            t2 = dt.datetime.strptime(found_end, '%H:%M:%S')
            total = t2-t1
            total_seconds = abs(total.total_seconds())
            total_session_time = str(total)
        except AttributeError:
            found_start = ''
            found_end = ''
        
        # Travel path
        travel_path = ""
        first_page = True
        for page in range(len(all_pages_visited)):
            if first_page:
                travel_path = travel_path + str(all_pages_visited[page])
                first_page = False
            else:
                travel_path = travel_path + " -> "+ str(all_pages_visited[page])

        # Remove duplicates from pages_visited
        pages_visited = list(dict.fromkeys(all_pages_visited))
                
        print("\nNODE",node+1,"ANALYSIS COMPLETE")        
        print("NODE",node+1,"ACTION BREAKDOWN:")
        print("Session start:",session_start_dt)
        print("Session end:",session_end)
        print("Total session time:",total_session_time)
        #print("(total seconds):",total_seconds)
        #print("Data & time of actions:",action_date_times)
        #print("All pages visited:",all_pages_visited)
        print("Pages visited:",pages_visited)
        print("Total time spent on each page:",total_time_on_pages)
        print("Travel path:",travel_path)
        print("Time spent on each page sequentially:",instance_time_on_pages)

        return all_pages_visited, timeline_data, total_time_on_pages

def pageInterest(all_node_action, site_pages_visited, total_page_visits, total_time_on_pages):
    all_page_interests = {}
    # Search through log for pages and add those pages to a list
    pages = list(dict.fromkeys(site_pages_visited))
    total_site_time = sum(total_time_on_pages.values())
    for page in pages:
        freq = site_pages_visited.count(page)/total_page_visits
        time = total_time_on_pages[page]/total_site_time
        page_interest = (2*freq*time)/(freq+time)
        all_page_interests[page] = page_interest
    all_page_interests = {k: v for k, v in sorted(all_page_interests.items(), key =lambda item: item[1], reverse = False)}

    return all_page_interests
    #plt.bar(range(len(all_page_interests)), list(all_page_interests.values()), align='center')
    #plt.xticks(range(len(all_page_interests)), list(all_page_interests.keys()))
    #plt.show()
    
def nodeTravelGraph(pages_visited):
    rcParams['figure.figsize'] = 8,4
    sb.set_style('white')
    G = nx.DiGraph()
    label_dict = {}
    
    if not pages_visited:
        G = nx.gn_graph(1)
        label_dict.update({0: "Home"})
        return G, label_dict
        #nx.draw_circular(G, labels=label_dict, node_color='white', with_labels=True)
    else:
        n_pages = len(pages_visited)
        for i in range(n_pages):
            if i+1 == n_pages & n_pages != 1:
                label_dict.update({i: pages_visited[i]})
                break
            elif n_pages == 1:
                G = nx.gn_graph(n_pages)
                label_dict.update({i: pages_visited[i]})
            else:
                label_dict.update({i: pages_visited[i]})
                G.add_edge(i,i+1)
        
        return G, label_dict
##        nx.draw_circular(G, labels=label_dict, node_color='yellow', with_labels=True)
##    plt.show()

def nodeNetworkGraph(nodes_found):
    #rcParams['figure.figsize'] = 8,4
    sb.set_style('ticks')
    G = nx.DiGraph()
    label_dict = {}
    
    if nodes_found == 0:
        G = nx.gn_graph(1)
        label_dict.update({0: "No Nodes Found"})
        return G, label_dict
    else:
        for i in range(nodes_found):
            if i+1 == nodes_found & nodes_found != 1:
                label_dict.update({i: i+1})
                break
            elif nodes_found == 1:
                G = nx.gn_graph(nodes_found)
                label_dict.update({i: i+1})
            else:
                label_dict.update({i: i+1})
                G.add_edge(i,i+1)
        global node_pos
        node_pos = nx.circular_layout(G)
        #graph = nx.draw_networkx(G, pos=node_pos, labels = label_dict, node_color='yellow', with_labels=True)
        return G, label_dict, node_pos

#----------------------------------------------#

################################################
########## MAIN TRIGGER FUNCTIONS ##############
################################################

def analyseNodes(node_list,all_node_action, sessions_dt, sessions_t):
    site_pages_visited = []
    total_time_on_pages = {}
    for node in node_list:
        node_pages_visited, timeline_data, time_on_pages = nodeActionBreakdown(all_node_action,node, sessions_dt[node],sessions_t[node])
        for i in range(len(node_pages_visited)):
            site_pages_visited.append(node_pages_visited[i])
            if node_pages_visited[i] not in total_time_on_pages.keys():
                total_time_on_pages[node_pages_visited[i]] = 0
            else:
                pass
        for key in time_on_pages:
            if key in total_time_on_pages:
                total_time_on_pages[key] = total_time_on_pages[key] + int(time_on_pages[key])
            else:
                pass
    return site_pages_visited, total_time_on_pages
        
def analyseNode(node,all_node_action, sessions_dt, sessions_t):
    all_pages_visited, timeline_data, total_time_on_pages = nodeActionBreakdown(all_node_action, node, sessions_dt[node], sessions_t[node])
    G, label_dict = nodeTravelGraph(all_pages_visited)
    return G, label_dict, all_pages_visited, timeline_data

def fetchAccessLog():
    print("\nFETCHING HONEYPOT ACCESS LOG...")
    log = accessLog()
    print("ACCESS LOG ACQUIRED")
    print("CONVERTING ACCESS LOG INTO READABLE FORMAT...")
    log = delFavicon(log)
    print("ACCESS LOG NOW READY FOR ANALYSIS\n")
    return log

def networkAnalysisProtocol():
    log = fetchAccessLog()
    print("SCANNING ACCESS LOG FOR NODES...")
    all_node_action, nodes_found, total_page_visits, sessions_dt, sessions_t = scanForNodeAction(log)
    print("ANALYSING NODES...")
    node_list = list(all_node_action.keys())
    site_pages_visited, total_time_on_pages = analyseNodes(node_list, all_node_action, sessions_dt, sessions_t)
    all_page_interests = pageInterest(all_node_action, site_pages_visited, total_page_visits, total_time_on_pages)
    G, label_dict, node_pos = nodeNetworkGraph(nodes_found)
    return nodes_found, G, label_dict, node_pos, all_page_interests

def nodeAnalysisProtocol(node):
    log = fetchAccessLog()
    print("SCANNING ACCESS LOG FOR NODE",node+1,"...")
    all_node_action, nodes_found, total_page_visits, sessions_dt, sessions_t = scanForNodeAction(log)
    print("ANALYSING NODE",node+1,"...")
    G, label_dict, all_pages_visited, timeline_data = analyseNode(node, all_node_action, sessions_dt, sessions_t)
    return nodes_found, G, label_dict, all_pages_visited, timeline_data

#----------------------------------------------#
def getThreatMovement(threat):
    file_name = "experiment_data/profile_data/"+threat+"_data.log"
    f = open(file_name, "r")
    log = delFavicon(f)
    all_node_action, nodes_found, total_page_visits, sessions_dt, sessions_t = scanForNodeAction(log)
    node_list = list(all_node_action.keys())
    threat_pages_visited = []
    for node in node_list:
        G, label_dict, all_pages_visited, timeline_data = analyseNode(node, all_node_action, sessions_dt, sessions_t)
        threat_pages_visited.append(all_pages_visited)
    return threat_pages_visited
