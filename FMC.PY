import requests
import json
import collections
from urllib.request import urlopen, Request
from collections import defaultdict 
import time
from requests.auth import HTTPBasicAuth
import getpass
import csv

#Man skal indtaste et gyldigt account før scriptet kører
username = input('Enter Username:')  
password = getpass.getpass("Enter Password:")
tokenUrl = ('URL som generer Token')
#login info vil dermed blive sendt afsted i post request får at få generet en token
tokenResponse = requests.post(tokenUrl, auth=HTTPBasicAuth(username, password), verify=False)

xToken = tokenResponse.headers.get("X-auth-access-token")
 
headers = {
      'X-auth-access-token': xToken
}
 
#Url hvor jeg kan hente liste af access-policies fra FMC
urlAccessPolicies = ('Liste af accesspolicies')
 
responseAccesssPolicies = requests.get(urlAccessPolicies, headers=headers, verify=False)
#response/dataen hentet fra api kaldet
contentAccessPolicies = responseAccesssPolicies.content
accessPolicies = json.loads(contentAccessPolicies)



def get_ids():
 
      # initalisere en tom dictionarry som jeg skal bruge senere til det hentede data fra api kaldene
      full_accesspoicy_dict={}
      # clear output file
      outputreportcsvFile=open("outputFMC.csv","w")
      csvwriter = csv.writer(outputreportcsvFile, lineterminator='\n')
      csvwriter.writerow(['itemDeviceId','accesspolicyid',"SourceNetworksName",'DestinationNetworksName','Protocols','DestinationPortsName','Ports','hitCount'])
      outputreportcsvFile.close()
 
        #--------------------- Start på access-policy og rule --------------------------
      itemsAccessPolicicy = accessPolicies["items"]
 
      urlDevicesId = ('Liste af forskellige devices')
      responseDevicesId = requests.get(urlDevicesId, headers=headers, verify=False)
      contentDevicesId = responseDevicesId.content
      devicesId = json.loads(contentDevicesId)
 
      #Løber igennem hver access-policy og finder access-policy rule
      for itemPolicy in itemsAccessPolicicy:
         
            if "id" in itemPolicy:
                #henter id
                accessId = itemPolicy.get("id")
                if accessId not in full_accesspoicy_dict:
                    full_accesspoicy_dict[accessId]={}
 
                #henter access-rules for accessPolicicy:
                urlAccessRules = (f'')#henter accesrules hvis accessID er tilføjet. Så + accessID til urlen
                response = requests.get(urlAccessRules, headers=headers, verify=False)
                content = response.content
                read_contentAccessRules = json.loads(content)
 
                #henter access-rules from api kald
                try:
                    itemsAccessRules = read_contentAccessRules['items']
                except:
                    itemsAccessRules = None
                    print("unable to parse result in name,source,dest part^" + str(itemsAccessRules))
                    continue
      
 
                for ruleIndex, itemAccessRule in enumerate(itemsAccessRules):
                    #Her er eksempel på strukturen i "3 lags dictionarien", uddybes i rapporten
                    #full_accesspoicy_dict={"DestinationPortsName":"","Ports":""}
                    # full_accesspoicy_dict={"ASDASD-234dsf3-asdas4":{"1":{"DestinationNetworksName":"1.2.3.4","Ports":"443" , etc},
                    #                                                 "2":{"DestinationNetworksName":".3.3.3.3","Ports":"80" , etc},
                    #                                                 "2":{"DestinationNetworksName":"any","Ports":"" , etc}},
                    #                       {"AAAAAAd-BBBBBB-CCCCCC":{"1":{"DestinationNetworksName":"5.5.5.5","Ports":"443" , etc},
                    #                                                 "2":{"DestinationNetworksName":"any","Ports":"80" , etc},
                    #                                                 "2":{"DestinationNetworksName":"any","Ports":"" , etc},
                    #                                                }
                    #                                                           
                    # }
                    #Hvis der ikke er værdier ved hver access-policyID, laves en basic dictionary for hver ID
                    if ruleIndex not in full_accesspoicy_dict[accessId]:
                            #Udfylder ruleindex med tomme værdier
                            full_accesspoicy_dict[accessId][ruleIndex]={"DestinationPortsName":"","Ports":"","Protocols":"", "SourceNetworksName":"", "DestinationNetworksName":",","hitCount":None}
                    #hvis prop findes og ikke er tom/null, så fyld værdierne i dict
                    if "destinationPorts" in itemAccessRule:
                            #henter en liste af ønskede props inde i accessrule, også laver jeg en komma-separeret string liste af de pågælende elementer, fx ["host1","host2","host3"] til "host1,host2,host3".
                            itemProps = itemAccessRule.get("destinationPorts").get("objects") or itemAccessRule.get("destinationPorts").get("literals")
                            for prop in itemProps:
                                if str(prop.get('name')) not in full_accesspoicy_dict[accessId][ruleIndex]["DestinationPortsName"]:
                                        full_accesspoicy_dict[accessId][ruleIndex]["DestinationPortsName"]=full_accesspoicy_dict[accessId][ruleIndex]["DestinationPortsName"] + str(prop.get('name'))+',' 
                                if str(prop.get('port')) not in full_accesspoicy_dict[accessId][ruleIndex]["Ports"]:
                                        full_accesspoicy_dict[accessId][ruleIndex]["Ports"]=full_accesspoicy_dict[accessId][ruleIndex]["Ports"] + str(prop.get('port'))+','
                                if str(prop.get('protocol')) not in full_accesspoicy_dict[accessId][ruleIndex]["Protocols"]:
                                        full_accesspoicy_dict[accessId][ruleIndex]["Protocols"]= full_accesspoicy_dict[accessId][ruleIndex]["Protocols"] + str(prop.get('protocol'))+','
                    if "sourceNetworks" in itemAccessRule:
                            itemProps = itemAccessRule.get("sourceNetworks").get("objects") or itemAccessRule.get("sourceNetworks").get("literals")
                            for prop in itemProps: 
                                if str(prop.get('name')) not in full_accesspoicy_dict[accessId][ruleIndex]["SourceNetworksName"]:
                                        full_accesspoicy_dict[accessId][ruleIndex]["SourceNetworksName"]=full_accesspoicy_dict[accessId][ruleIndex]["SourceNetworksName"] + str(prop.get('name'))+','
                    if "destinationNetworks" in itemAccessRule:
                            itemProps = itemAccessRule.get("destinationNetworks").get("objects") or itemAccessRule.get("destinationNetworks").get("literals")
                            for prop in itemProps: 
                                if str(prop.get('name')) not in full_accesspoicy_dict[accessId][ruleIndex]["DestinationNetworksName"]:
                                        full_accesspoicy_dict[accessId][ruleIndex]["DestinationNetworksName"]=full_accesspoicy_dict[accessId][ruleIndex]["DestinationNetworksName"] + str(prop.get('name'))+','
                #--------------------- Slut på access-policy og rule --------------------------
 
                #------------------------ start på hitcounts analyse for hver device access-policy 
                itemsDevicesRecords = devicesId["items"]
                for itemDeviceId in itemsDevicesRecords:   
                    #henter detaljer om access-policy som er tilknyttet til pågældende device        
                    deviceRecordId = itemDeviceId.get("id")
                    urlHitCounts = (f'')#accessid og deviceRecordID skal tilføjes i urlen for at få hentet hitcounts
                    response = requests.get(urlHitCounts, headers=headers, verify=False)
                    content = response.content
                    read_contentHitcounts = json.loads(content)
    
                    itemsHitcount = None
                    time.sleep(0.4)
                    #Hvis ingen exception, er der policy tilknyttet til device, og scriptet skal dermed forsætte analysen til hitcounts
                    try:
                        itemsHitcount = read_contentHitcounts['items']
                        print('HERE IS DEVICEID')
                        print(itemDeviceId['name'])
                    except:
                            print("unable to parse result in hitcount part " + str(itemsHitcount))
                            continue
                    print('---------------------------------------------------------------------------')    
                
                    #henter hitcounts og matcher det med den pågælende access-policy(ruleIndex)
                    for ruleIndex, hitCount in enumerate(itemsHitcount):
                        if 'hitCount' in hitCount:
                            if ruleIndex not in full_accesspoicy_dict[accessId]:
                                    full_accesspoicy_dict[accessId][ruleIndex]={}
                            if hitCount['hitCount'] > 0:
                                    full_accesspoicy_dict[accessId][ruleIndex]["hitCount"]=hitCount['hitCount']
                            elif hitCount['hitCount'] == 0:
                                    full_accesspoicy_dict[accessId][ruleIndex]["hitCount"]=hitCount['hitCount']
                        else:
                            print('ERROR HITCOUNT')
                            print(itemsHitcount)
 
                    #Skriver output for policy og hitcounts i CSV-fil
                    with open('outputFMC.csv', 'a') as csvfile:
                            csvwriter = csv.writer(csvfile, lineterminator='\n')
                            #løber igennem policyIDs
                            for accesspolicyid, policyitems in full_accesspoicy_dict.items():
                                #Løber igennem policyrules
                                for policyitem, details in policyitems.items():
                                        csvwriter.writerow([itemDeviceId['name'],accesspolicyid,details["SourceNetworksName"],details['DestinationNetworksName'],details['Protocols'],details['DestinationPortsName'],details['Ports'],details['hitCount']])
 
print(get_ids())
 
