import csv
import  os
import threading
def my_csv_reader(path):
    with open(path) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        Critical_count = 0
        High_Count = 0
        Medium_Count = 0
        Low_count = 0
        info_count = 0
        with open('Critical.csv', 'a+',newline='',encoding='utf8') as critical_file, open('High.csv', 'a+',newline='',encoding='utf8') as high_file,open('Medium.csv', 'a+',newline='',encoding='utf8')as medium_file:
            csvcritical=csv.writer(critical_file)
            csvhigh=csv.writer(high_file)
            csvmedium=csv.writer(medium_file)
            for row in csv_reader:
                type = row[3]
                cve=row[1]
                cvss=row[2]
                risk=row[3]
                host=row[4]
                port=row[6]
                name=row[7]
                solution=row[10]
                Plugin_output=row[12]
                data=[row[1],row[2],row[3],row[4],row[6],row[7],row[10],row[12]]
                if type == "Critical":
                    Critical_count = Critical_count + 1
                    csvcritical.writerow(data)
                elif type == "High":
                    High_Count += 1
                    csvhigh.writerow(data)
                elif type == "Medium":
                    Medium_Count += 1
                    csvmedium.writerow(data)
                elif type == "Low":
                    Low_count += 1
                elif type == "None":
                    info_count += 1
        return (Critical_count,High_Count,Medium_Count,Low_count,info_count)
folder= input("#please enter your csv folder path:\n")
total_Critical=0
total_High=0
total_Medium=0
total_low=0
total_info=0
with open('Critical.csv', 'a+', newline='', encoding='utf8') as critical_file, open('High.csv', 'a+', newline='',encoding='utf8') as high_file, open('Medium.csv', 'a+', newline='', encoding='utf8')as medium_file:
    headers=['CVE','CVSS','Risk','Host','Port','Name','Solution','Plugin_Output']
    csvcritical = csv.writer(critical_file)
    csvhigh = csv.writer(high_file)
    csvmedium = csv.writer(medium_file)
    csvcritical.writerow(headers)
    csvhigh.writerow(headers)
    csvmedium.writerow(headers)
for r,d,f in os.walk(folder):
    for file in f:
        file_path=folder+ "\\" + file
        range_count=my_csv_reader(file_path)
        total_Critical+=int(range_count[0])
        total_High += int(range_count[1])
        total_Medium += int(range_count[2])
        total_low += int(range_count[3])
        total_info += int(range_count[4])
print("number of Critical " ,total_Critical)
print("number of High " , total_High)
print("number of Medium " , total_Medium)
print("number of low " , total_low)
print("number of info " , total_info)







