import threading
import time
import os
import pyshark
import numpy as np
from joblib import dump, load
from time import sleep
import subprocess
list_cap=[]
class MonThread (threading.Thread):
	def __init__(self, id):      # jusqua = donnée supplémentaire
        	threading.Thread.__init__(self)  # ne pas oublier cette ligne
        	# (appel au constructeur de la classe mère)
        	self.id = id           # donnée supplémentaire ajoutée à la classe
	def run(self):
		
				
			
		if self.id == 1:
			#creation de fichier
			file0 = open("FlowStatsfile.csv","w")
			file0.write("Ip source,Ip destination,Port source,Port destination,Total Length of Fwd Packets,Fwd Packet Length Mean,Bwd Packet Length Mean,Flow Bytes/s,Flow Packets/s,Bwd Header Length,Bwd Packets/s,Max Packet Length,PSH Flag Count,ACK Flag Count,Average Packet Size,Avg Bwd Segment Size,Subflow Fwd Bytes,min_seg_size_forward,Label\n")
			file1 = open("block.csv","w")
			
			file0.close()
			file1.close()
			file3 = open("pos.txt","w")
			file3.write("0")
			file3.close()
			while True:
				
				
				if len(list_cap) !=0:
					#print("taill de la liste a collecter",len(list_cap))
					cap = list_cap[0]
					del list_cap[0]
					flow={}
					for p in cap:
						idIp = [p.ip.src,p.ip.dst]
						idPort =[p.tcp.srcport,p.tcp.dstport]
						idFlow = str(max(idIp))+ '-' + str(min(idIp)) + '-' + str(max(idPort)) + '-' + str(min(idPort))
						if flow.get(idFlow) == None:
							flow[idFlow] = [p]
						else:
							flow[idFlow].append(p)

					#for cle,valeur in flow.items():
					#	print(cle,valeur)	
					
					
					#total length of packets
					flowLengthTot = {}
					for cle,valeur in flow.items():
						for p in valeur:
							if flowLengthTot.get(cle) == None:
								flowLengthTot[cle] = int(p.length)
							else:
								flowLengthTot[cle] = flowLengthTot[cle] + int(p.length)

					#total length of packets Fwd
					flowLengthTotFwd = {}
					for cle,valeur in flow.items():
						srcFwd = valeur[0].ip.src
						for p in valeur:
							if srcFwd == p.ip.src: 
								if flowLengthTotFwd.get(cle) == None:
									flowLengthTotFwd[cle] = int(p.length)
								else:
									flowLengthTotFwd[cle] = flowLengthTotFwd[cle] + int(p.length)

					flowLengthTotBwd = {}
					for cle,valeur in flow.items():
						dstBwd = valeur[0].ip.dst
						existe =False	
						for p in valeur:
							if dstBwd == p.ip.src: 
								if flowLengthTotBwd.get(cle) == None:
									flowLengthTotBwd[cle] = int(p.length)
								else:
									flowLengthTotBwd[cle] = flowLengthTotBwd[cle] + int(p.length)
								existe = True
						if existe == False:
							flowLengthTotBwd[cle] = 0.0
							
							
								
												
					#Fwd packet length mean
					flowLengthMeanFwd = {}
					for cle,valeur in flow.items():
						srcFwd = valeur[0].ip.src
						cpt = 0	
						for p in valeur:
							if srcFwd == p.ip.src: 
								cpt = cpt + 1	
						flowLengthMeanFwd[cle] = float(flowLengthTotFwd.get(cle))/float(cpt)

					

					#Bwd packet length mean
					flowLengthMeanBwd = {}
					for cle,valeur in flow.items():
						dstBwd = valeur[0].ip.dst
						cpt = 0	
						existe = False
						for p in valeur:
							if dstBwd == p.ip.src:
								existe = True 
								cpt = cpt + 1
						if existe == True:	
							flowLengthMeanBwd[cle] = float(flowLengthTotBwd.get(cle))/float(cpt)
						else:
							flowLengthMeanBwd[cle]=0.0
										



					#Flow Bytes/s
					flowBytesPers = {}
					for cle,valeur in flow.items():
						time = 0.0	
						for p in valeur:
							if time < float(p.tcp.time_relative):
								time = float(p.tcp.time_relative)
								
						if float(time)> 0.0:
							flowBytesPers[cle] = float(flowLengthTot.get(cle))/float(time)
						else:
							flowBytesPers[cle] = 0.0


						

					#flow paquet/s
					flowpacketPers = {}
					for cle,valeur in flow.items():
						time = 0.0	
						for p in valeur:
							if time < float(p.tcp.time_relative):
								time = float(p.tcp.time_relative)
						if float(time)> 0.0:
							flowpacketPers[cle] = float(len(valeur))/float(time)
						else:
							flowpacketPers[cle] = 0.0


					#for cle,valeur in flowpacketPers.items():
					#	print(cle,valeur)

					#flow Iat Mean
					#flow Iat Max
					#Bwd Header Length
					flowHeaderlengthBwd = {}
					for cle,valeur in flow.items():
						dstBwd = valeur[0].ip.dst
						existe = False
						for p in valeur:
							if dstBwd == p.ip.src: 
								existe = True 
								if flowHeaderlengthBwd.get(cle) == None:
									flowHeaderlengthBwd[cle] = int(p.tcp.hdr_len)+int(p.ip.hdr_len)+int(p.length)-int(p.ip.hdr_len)-int(p.tcp.hdr_len)-int(p.tcp.len)
								else:
									flowHeaderlengthBwd[cle] =flowHeaderlengthBwd[cle] +int(p.tcp.hdr_len)+int(p.ip.hdr_len)+int(p.length)-int(p.ip.hdr_len)-int(p.tcp.hdr_len)-int(p.tcp.len)
						if existe == False: 
							flowHeaderlengthBwd[cle] = 0
							

								
					#BWD paquet/s	
					flowpacketPersBwd = {}
					for cle,valeur in flow.items():
						time = 0.0
						cpt = 0	
						dstBwd = valeur[0].ip.dst
						exist = False
						for p in valeur:
							if dstBwd == p.ip.src: 
								exist= True
								cpt = cpt + 1
								if time < float(p.tcp.time_relative):
									time = float(p.tcp.time_relative)
						if exist== True:
							flowpacketPersBwd[cle] = float(cpt)/float(time)
						else:
							flowpacketPersBwd[cle] = 0.0

					#Max Packet Lentgh
					flowMaxPacketLength = {}
					for cle,valeur in flow.items():
						maxi = 0	
						for p in valeur:
							if maxi < int(p.length):
								maxi = int(p.length)
						flowMaxPacketLength[cle] = maxi


					#Packet Lentgh Mean
					#Psh Flag Count
					flowPshFlagCount = {}
					for cle,valeur in flow.items():
						for p in valeur:
							if flowPshFlagCount.get(cle) == None:
								flowPshFlagCount[cle] = int(p.tcp.flags_push)		
							else:	
								flowPshFlagCount[cle] = flowPshFlagCount.get(cle)+ int(p.tcp.flags_push)


					#Ack Flag Count
					flowAckFlagCount = {}
					for cle,valeur in flow.items():
						for p in valeur:
							if flowAckFlagCount.get(cle) == None:
								flowAckFlagCount[cle] = int(p.tcp.flags_ack)		
							else:	
								flowAckFlagCount[cle] = flowAckFlagCount.get(cle)+ int(p.tcp.flags_ack)

						
					#Average Packet size
					flowAvergePacketSize = {}
					for cle,valeur in flow.items():
						flowAvergePacketSize[cle] = float((flowLengthTot[cle]))/float(len(valeur))


					#Averge Bwd Segment Size
					flowAvergeSegmentSizeBwd = {}
					for cle,valeur in flow.items():
						dstBwd = valeur[0].ip.dst
						cpt = 0
						exist = False
						for p in valeur:
							if dstBwd == p.ip.src:
								exist = True 
								cpt = cpt + 1
						if exit == True:	
							flowAvergeSegmentSizeBwd[cle] = float(flowLengthTotBwd.get(cle))/float(cpt)
						else:
							flowAvergeSegmentSizeBwd[cle] = 0.0



					#subflow FWD Bytes
					flowsubflowFwdBytes = {}
					for cle,valeur in flow.items():
						srcFwd = valeur[0].ip.src	
						for p in valeur:
							if srcFwd == p.ip.src: 
								if flowsubflowFwdBytes.get(cle) == None:
									flowsubflowFwdBytes[cle] = int(p.length)
								else:
									flowsubflowFwdBytes[cle] = flowsubflowFwdBytes[cle] + int(p.length)


					#init_win_bytes_forward
					#init_win_bytes_Backward
					#min_seg_size_forward
					flowMinSegSizeForward = {}
					for cle,valeur in flow.items():
						srcFwd = valeur[0].ip.src	
						mini = int(p.tcp.hdr_len)+int(p.tcp.len)
						for p in valeur:
							if srcFwd == p.ip.src: 
								if mini > int(p.tcp.hdr_len)+int(p.tcp.len):
									mini = int(p.tcp.hdr_len)+int(p.tcp.len)
						flowMinSegSizeForward[cle] = mini


	
					fparams = np.zeros((1, 14))
					rf = load("test_modelRF") 
					ligitimate_trafic = 0
					ddos_trafic = 0 
					file0 = open("FlowStatsfile.csv","a")
					file1 = open("block.csv","a")
					for cle in flow.keys():
						
						fparams[:,0] = flowLengthTotFwd.get(cle)
						fparams[:,1] = flowLengthMeanFwd.get(cle)
						fparams[:,2] = flowLengthMeanBwd.get(cle)
						fparams[:,3] = flowBytesPers.get(cle)
						fparams[:,4] = flowpacketPers.get(cle)
						fparams[:,5] = flowHeaderlengthBwd.get(cle)
						fparams[:,6] = flowpacketPersBwd.get(cle)
						fparams[:,7] = flowMaxPacketLength.get(cle)
						fparams[:,8] = flowPshFlagCount.get(cle)
						fparams[:,9] = flowAckFlagCount.get(cle)
						fparams[:,10] =flowAvergePacketSize.get(cle)
						fparams[:,11] =flowAvergeSegmentSizeBwd.get(cle)	
						fparams[:,12] = flowsubflowFwdBytes.get(cle)
						fparams[:,13] = flowMinSegSizeForward.get(cle)
						ypred = rf.predict(fparams)
						#print(ypred)		
						if ypred == 0:
							ligitimate_trafic = ligitimate_trafic + 1
						else:
							p = flow.get(cle)
							ipsrc = p[0].ip.src
							ddos_trafic = ddos_trafic + 1
						
						file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(idIp[0],idIp[1],idPort[0],idPort[1],flowLengthTotFwd.get(cle),flowLengthMeanFwd.get(cle),flowLengthMeanBwd.get(cle),flowBytesPers.get(cle),flowpacketPers.get(cle),flowHeaderlengthBwd.get(cle),flowpacketPersBwd.get(cle),flowMaxPacketLength.get(cle),flowPshFlagCount.get(cle),flowAckFlagCount.get(cle),flowAvergePacketSize.get(cle),flowAvergeSegmentSizeBwd.get(cle),flowsubflowFwdBytes.get(cle),flowMinSegSizeForward.get(cle),))
						
						if(ypred == 0):						
							file0.write(",{}\n".format("normal"))
						else:
							file0.write(",{}\n".format("slow DOS"))
					#print(ligitimate_trafic,ddos_trafic )
						
					
					
					 	

					#print(flowLengthTotFwd.get(cle),flowLengthMeanFwd.get(cle),flowLengthMeanBwd.get(cle),flowBytesPers.get(cle),flowpacketPers.get(cle),flowHeaderlengthBwd.get(cle),flowpacketPersBwd.get(cle),flowMaxPacketLength.get(cle),flowPshFlagCount.get(cle),flowAckFlagCount.get(cle),flowAvergePacketSize.get(cle),flowAvergeSegmentSizeBwd.get(cle),flowsubflowFwdBytes.get(cle),flowMinSegSizeForward.get(cle))
					#sleep(10)		
					
					if len(flow.keys()) != 0:
						if (ligitimate_trafic / len(flow.keys())*100) > 80:
							print("trafic ligitimate...")
							print("------------------------------------")
							file1.write("{},{},{},{},{}\n".format(idIp[0],idIp[1],idPort[0],idPort[1],"noraml"))
							
						else:
							print("trafic d'attaque...")
							victim = str(idIp[1])[-1]
							print("La victime est l'hote: h{}".format(victim))
							print("------------------------------------")
							file1.write("{},{},{},{},{}\n".format(idIp[0],idIp[1],idPort[0],idPort[1],"slow DOS"))
					
		
					file0.close()
					file1.close()	
					sleep(3)
					cap = None

       

def main():
	
	m = MonThread(1)  
	m.start() 
	
	while True:
		capture = pyshark.LiveCapture(interface='h3-eth0',output_file = '/home/capture/capt.pcap',display_filter='tcp')
		capture.sniff(timeout=10)		
		cap = [pkt for pkt in capture._packets]
		if(cap != None):		
			list_cap.append(cap)
		#print(list_cap)


if __name__=="__main__":
	main()





