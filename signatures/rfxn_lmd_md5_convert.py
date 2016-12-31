import json


database = {"Database_Name":"doppelstern.hdb","Database_Hash":[]}


#{"Malware_Name":"Doppelstern.hdb.Is.Dead.RIP","Malware_Hash":"3b583df09ec829197e03819fddf45f84"}

f = open('md5.dat')
content = f.readlines()
for line in content:
    malware = line.split(':')
    database["Database_Hash"].append({'Malware_Name': malware[1].strip(), 'Malware_Hash': malware[0]})

with open('rfxn_lmd.json', 'w') as outfile:
    json.dump(database, outfile)
