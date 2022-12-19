import os
os.system("curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000001")
#os.system('curl -X POST -d  \'{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32", "nw_proto": "TCP","actions": "DENY", "priority": "10"}\' http://localhost:8080/firewall/rules/0000000000000001')
#os.system('curl -X POST -d  \'{"nw_src": "10.0.0.2/32", "nw_dst": "10.0.0.1/32", "nw_proto": "TCP","actions": "DENY", "priority": "10"}\' http://localhost:8080/firewall/rules/0000000000000001')

os.system('curl -X DELETE -d \'{"rule_id": "5"}\' http://localhost:8080/firewall/rules/0000000000000001')
						
os.system('curl -X DELETE -d \'{"rule_id": "6"}\' http://localhost:8080/firewall/rules/0000000000000001')
