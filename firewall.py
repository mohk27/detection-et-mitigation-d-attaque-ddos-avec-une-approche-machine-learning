import numpy as np
import pandas as pd
import csv 
import os
import time
import subprocess
import re	
			
def main():
	
	print("initalisation du firwall\n")
	os.system("curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000001")
	os.system('curl -X DELETE -d \'{"rule_id": "all"}\' http://localhost:8080/firewall/rules/0000000000000001')
	#var = os.system('curl -X GET -d  \'{"switch": "all"}\' http://localhost:8080/firewall/rules/0000000000000001')
	
	print("\n")	
	os.system('curl -X POST -d  \'{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32", "nw_proto": "TCP"}\' http://localhost:8080/firewall/rules/0000000000000001')
	print("\n")
	os.system('curl -X POST -d  \'{"nw_src": "10.0.0.2/32", "nw_dst": "10.0.0.1/32", "nw_proto": "TCP"}\' http://localhost:8080/firewall/rules/0000000000000001')
	print("\n")
	print("--------------------------------------------------------------------------")
	existe = True
	try:	
		var = open("pos.txt","r")
	except FileNotFoundError as e:	
		existe = False
	if(existe == True):	
		ch = var.read()
		if(ch == ""):
			pos = 0
		else:
			pos = int(ch)
		var.close()
	else:
		pos = 0
	ch = subprocess.getoutput('curl -X GET -d  \'{"switch": "all"}\' http://localhost:8080/firewall/rules/0000000000000001')
	rule_id_liste = re.findall("rule_id\": \d+", ch)
	if(rule_id_liste != []):	
		rule_id_chaine = re.findall("\d+", rule_id_liste[-1])
	if(rule_id_liste == []):
		rule = 2
	else:
		rule = int(rule_id_chaine[0])	
	while True:
		existe = True
		try:		
			f = open("block.csv","r")
		except FileNotFoundError as e:
			existe = False

		if(existe != False):		
			myReader = csv.reader(f)
			cpt = 0
			
			for row in myReader:
				
				if cpt >= pos : 
					cpt =cpt +1
					var = open("pos.txt","w")
					var.write(str(cpt))
					var.close()				
					if(row[4] == 'slow DOS'):
						print("Desactivation du trafic d'attaque pour la source : {}\n".format(row[0]))

						print("Ajout de regles:")
						os.system('curl -X POST -d  \'{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32", "nw_proto": "TCP","actions": "DENY", "priority": "10"}\' http://localhost:8080/firewall/rules/0000000000000001')
						print("\n")
						os.system('curl -X POST -d  \'{"nw_src": "10.0.0.2/32", "nw_dst": "10.0.0.1/32", "nw_proto": "TCP","actions": "DENY", "priority": "10"}\' http://localhost:8080/firewall/rules/0000000000000001')
						print("\n")
						rule = rule + 2
						time.sleep(10)
						print("Activation du trafic pour la source : {}\n".format(row[0]))
						print("Ajout de regles:")
						ch1 = 'curl -X DELETE -d \'{"rule_id": "'+str(rule-1)+'"}\' http://localhost:8080/firewall/rules/0000000000000001'
						os.system(ch1)
						print("\n")
						os.system('curl -X DELETE -d \'{"rule_id": "'+str(rule)+'"}\' http://localhost:8080/firewall/rules/0000000000000001')
						print("\n")
						print("--------------------------------------------------------------------------")
				else:
					cpt =cpt +1
					
				
				
			pos = cpt
			
		
			f.close()
		
if __name__=="__main__":
	main()
	



#%df = pd.read_csv ('FlowStatsfile.csv')
#	print(df)
#	for i in range(len(df)):
#		print(str(df.iloc[i,0])+ " "+str(df.iloc[i,1])+ " "+str(df.iloc[i,2])+ " "+str(df.iloc[i,3])+ " "+str(df.iloc[i,4])+ " "+str(df.iloc[i,5])+ " "+str(df.iloc[i,6])+ " "+str(df.iloc[i,7])+ " "+str(df.iloc[i,8])+ " "+str(df.iloc[i,9])+ " "+str(df.iloc[i,10])+ " "+str(df.iloc[i,11])+ " "+str(df.iloc[i,12])+ " "+str(df.iloc[i,13]))
#		df.drop(i)

