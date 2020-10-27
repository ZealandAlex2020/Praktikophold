import requests
import json
import collections
from urllib.request import urlopen, Request
from collections import defaultdict 
import time
from requests.auth import HTTPBasicAuth
import getpass
import re
import csv
 
#Man skal indtaste et gyldigt account før scriptet kører
username = input('Enter Username:')  
password = getpass.getpass("Enter Password:")
aclNamesUrl = ('aclNames URL')
 
headers = {
      'User-Agent':'REST API Agent'
}
aclNameResponse = requests.get(aclNamesUrl, auth=HTTPBasicAuth(username, password), headers=headers, verify=False)
contentAclNames = aclNameResponse.content
aclNames = json.loads(contentAclNames)
#Henter aclnames fra REST api kald
 
#clear output file
outputreportcsvFile=open("outputASA.csv","w")
csvwriter = csv.writer(outputreportcsvFile, lineterminator='\n')
csvwriter.writerow(["SourceNetworksName",'DestinationNetworksName','Protocols','Ports','hitCount'])
outputreportcsvFile.close()
 
#Løber igennem hver aclname
for aclName in aclNames["items"]:
      #Hver aclname vil blive sendt i hver sin  post request body, så jeg kan få detaljeret regler for hver accesslist
      #ASA er der ikke et direkte api-kald for at få hitcounts, så jeg nød til at kalde en show-command direkte og analyser det (regex)
      payload = {"commands":["show access-list {}".format(aclName["ACLName"])]}  
      headers = {
            'User-Agent':'REST API Agent',
            'Content-Type':'application/json',
      }
 
      urlHitcount = ('Her henter jeg et string response')
      responseHitCount = requests.post(urlHitcount, headers=headers, json=payload, auth=HTTPBasicAuth(username, password),verify=False)
      dataJson = responseHitCount.json()
      regexDataList = dataJson.get("response")
      #api data/response
 
      
      #Konverter string response fra api-kaldet til en liste af seperate regler
      regexDataString = ''.join(regexDataList)
      listregexDataString = regexDataString.split("\n")
      #Kører regex expression for analysere resultatet/response  
      regex = r"(\S+\s|\s+\S+\s)(\S+\s)+(line)\s(\d+)\s(extended)\s(permit|deny)\s?(\S+\s)?(\S+\s)?(\S+\s)?(\S+\s)?(\S+\s)?(\S+\s)?(\S+\s)?(\S+\s)?(\S+\s)?(\S+\s)?([^(]\S+\s)([(]hitcnt[=]\d+[)])?([(]inactive[)]\s\S+|\s\S+)"
      
      for rule in listregexDataString:
            try:
                  #Formater resultatet/response fra regex med grupper, så jeg kun får de værdier jeg skal bruge og ikke hele linjen med alle værdierne
                  rule=rule.lstrip()
                  ASAmatches = re.search(regex, rule)
                  sourceNetworksName=ASAmatches.group(8,9)
                  destinationNetworksName=ASAmatches.group(10,11)
                  protocols=ASAmatches.group(7)
                  ports=ASAmatches.group(12,13,14,15,16,17)
                  hitCount=ASAmatches.group(18)
                    #Output til CSV-fil
                  with open('outputASA.csv', 'a') as csvfile:
                        csvwriter = csv.writer(csvfile, lineterminator='\n')
                        csvwriter.writerow([sourceNetworksName,destinationNetworksName,protocols,ports,hitCount])
            except:
                  print(rule, "FAILED")
                  print('------------------------------------')
 
