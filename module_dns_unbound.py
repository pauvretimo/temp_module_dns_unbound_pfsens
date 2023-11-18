import json
import  ipaddress

_dns_table =     {
        "172.16.1.0/24": {
            "challs.nobrackets.lan.": "10.0.1.2",
            "box1.nobrackets.lan.": "10.0.1.3",
            "box2.nobrackets.lan.": "10.0.1.4"
        },
        "172.16.2.0/24": {
            "challs.nobrackets.lan.": "10.0.2.2",
            "box1.nobrackets.lan.": "10.0.2.3",
            "box2.nobrackets.lan.": "10.0.2.4"
        },
        "172.16.3.0/24": {
            "challs.nobrackets.lan.": "10.0.3.2",
            "box1.nobrackets.lan.": "10.0.3.3",
            "box2.nobrackets.lan.": "10.0.3.4"
        },
        "172.16.4.0/24": {
            "challs.nobrackets.lan.": "10.0.4.2",
            "box1.nobrackets.lan.": "10.0.4.3",
            "box2.nobrackets.lan.": "10.0.4.4"
        },
        "172.16.5.0/24": {
            "challs.nobrackets.lan.": "10.0.5.2",
            "box1.nobrackets.lan.": "10.0.5.3",
            "box2.nobrackets.lan.": "10.0.5.4"
        },
        "172.16.6.0/24": {
            "challs.nobrackets.lan.": "10.0.6.2",
            "box1.nobrackets.lan.": "10.0.6.3",
            "box2.nobrackets.lan.": "10.0.6.4"
        },
        "172.16.7.0/24": {
            "challs.nobrackets.lan.": "10.0.7.2",
            "box1.nobrackets.lan.": "10.0.7.3",
            "box2.nobrackets.lan.": "10.0.7.4"
        }
    }

dns_table = {}

def init(id, cfg): 
   global dns_table
   global _dns_table
   for ip, data in _dns_table.items():
      dns_table[ipaddress.ip_network(ip)] = data
   return True

def deinit(id): return True

def inform_super(id, qstate, superqstate, qdata): return True

def operate(id, event, qstate, qdata):
    try:
    # when a dns query arrive
        if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
            # get the source ip
            addr = ipaddress.ip_address(q.addr)
            
            # check if the ip is in the table (networks)
            for network, rules in dns_table.items():
                print("1")
                if addr in network:
                    print("2")
                    # check if the domain is in the table (rules)
                    if qstate.qinfo.qname_str in rules.keys():
                        print("3")
                        res_ip = rules[qstate.qinfo.qname_str]

                        #create instance of DNS message (packet) with given parameters
                        msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
                        #append RR
                        if (qstate.qinfo.qtype == RR_TYPE_A) or (qstate.qinfo.qtype == RR_TYPE_ANY):
                           print("4")
                            msg.answer.append(qstate.qinfo.qname_str + " 10 IN A " + res_ip)
                            setTTL(qstate, 0)
                        if not msg.set_return_msg(qstate):
                            print("5")
                            qstate.ext_state[id] = MODULE_ERROR 
                            return True

                        #we don't need validation, result is valid
                        qstate.return_msg.rep.security = 2

                        qstate.return_rcode = RCODE_NOERROR
                        qstate.ext_state[id] = MODULE_FINISHED 
                        return True 
        #if ip from query is not in table, pass the query to validator  
        #pass the query to validator
        qstate.ext_state[id] = module_finished 
        return True
    except Exception as e:
        print("error")
        #if ip from query is not in table, pass the query to validator  
        #pass the query to validator
        qstate.ext_state[id] = module_finished 
        return True

    if event == MODULE_EVENT_MODDONE:
        log_info("pythonmod: iterator module done")
        qstate.ext_state[id] = MODULE_FINISHED 
        return True
      
    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
