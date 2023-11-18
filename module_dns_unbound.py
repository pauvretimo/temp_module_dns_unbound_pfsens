import json
import  ipaddress

dns_table = {}


def init(id, cfg): 
   global dns_table
   with open("/var/unbound/conf.json", 'r') as f:
      le_j = json.loads(f.read())
      for ip, data in le_j.items():
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
                if addr in network:
                    # check if the domain is in the table (rules)
                    if qstate.qinfo.qname_str in rules.keys():
                        res_ip = rules[qstate.qinfo.qname_str]

                        #create instance of DNS message (packet) with given parameters
                        msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
                        #append RR
                        if (qstate.qinfo.qtype == RR_TYPE_A) or (qstate.qinfo.qtype == RR_TYPE_ANY):
                            msg.answer.append("%s 10 IN %s" % qstate.qinfo.qname_str, res_ip)
                            setTTL(qstate, 0)
                        if not msg.set_return_msg(qstate):
                            qstate.ext_state[id] = MODULE_ERROR 
                            return True

                        #we don't need validation, result is valid
                        qstate.return_msg.rep.security = 2

                        qstate.return_rcode = RCODE_NOERROR
                        qstate.ext_state[id] = MODULE_FINISHED 
                        return True 
    except:
        #if ip from query is not in table, pass the query to validator  
        #pass the query to validator
        qstate.ext_state[id] = MODULE_WAIT_MODULE 
        return True

    if event == MODULE_EVENT_MODDONE:
        log_info("pythonmod: iterator module done")
        qstate.ext_state[id] = MODULE_FINISHED 
        return True
      
    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
