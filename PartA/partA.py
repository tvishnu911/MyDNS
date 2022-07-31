#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Sep 19 16:02:28 2021

@author: vishnutammishetti
"""

import dns.resolver
import time
import sys
#Funcs
def fetchResponse(queryText, rtype, targetIp):  # Used to make a call to the targetIp and return response
    query = dns.message.make_query(queryText, rtype, want_dnssec=False)  
    response = dns.query.udp(query, targetIp, timeout = 2)
    return response

def ipsIn(result): # Checks if there is an A record in the result set
    for i in result:
        if i.rdtype == 1:
            return True
    return False
def nssIn(result): # Checks if there is an NS record in the result set
    for i in result:
        if i.rdtype == 2:
            return True
    return False
def mxsIn(result): # Checks if there is an MX record in the result set
    for i in result:
        if i.rdtype == 15:
            return True
    return False

def printResult(url, rType, resultSet, timeTaken): # Used to print the result in the desire 'dig' command format
    print("QUESTION SECTION:")
    print("{}     IN      {}".format(url, rType))
    
    print("ANSWER SECTION:")
    if resultSet:
        print(resultSet[0])
        print("")
    print("Query time: {} msec".format(int(timeTaken)))
    print("When: {}".format(time.ctime()))
    print("MSG SIZE rcvd:", sys.getsizeof(resultSet))

def mainFunction(url, rType): # This is the main function, where the recursive call are called and the next level ip targets are updated
    # print("URL: ", url)
    for root in root_servers.values():
        try:
            response = fetchResponse(url, rType, root)
#             print(response)
            while not response.answer: # We run this as long as the answer field is empty
#                 print(response)
                if response.additional:
                    for val in response.additional:
    #                     print(val)
                        if val.rdtype == 1:
                            nextIp = str(val[0]) # We take the A record in additional to send the next request to this address
                            response = fetchResponse(url, rType, nextIp)
                            break

                else:
                    if response.authority:
                        for val in response.authority:
                            if val.rdtype == 2:
                                nameServer = str(val[0]) # If there is a name server, we uresolve this
                                break
                        nameServerResponse = mainFunction(nameServer, "A")
#                         print(nameServerResponse)
    #                     return
                        for i in nameServerResponse.answer:
                            foundNs = False
                            if i.rdtype == 1:
                                nextIp = i
#                                 print(nextIp)
                                response.additional = [nextIp] # If the resolved name server has an ip, we add it to the additional so that this can be called in next iteration
                                foundNs = True
                                break
                        if not foundNs:
                            return response
                        # If there is no name server as well, the authority section might contain the NS. Check dig www.google.com NS
            if nssIn(response.answer) and rType == "NS": # If the required type is NS and is found, we return
                return response
            if mxsIn(response.answer) and rType == "MX":# If the required type is MX and is found, we return
                return response
            if ipsIn(response.answer): # If the required type is A and is found, we return
                return response
            else:
                print("NO IPS")
                cname = None
                for i in response.answer:
                    if i.rdtype == 5:
                        print("Has CNAMES")
                        cname = str(i) # If it has cnames, we resolve this
                        
                        break
                if cname:
                    print("In loop")
                    response1 = mainFunction(str(i), rType)
#                     print(response1)
                    return (response1)
                else:
                    return response
#                     break
#                 return response
        except Exception as e:
#             raise e
#             print("Root {} didnt work mate".format(root))
            continue
        
def finalFunc(url, rtype): # This is the function where input is sent to the main function
    startTime = time.time()
    finalUrl = url[::]
    if url[:4] == "www.":
        finalUrl = finalUrl[4::]
    response = mainFunction(finalUrl, rtype)
#     print("Final response:\n")
#     print(response.answer)
    timeTaken = (time.time() - startTime)*10**3
    if response:
        printResult(url, rtype, response.answer, timeTaken)
    else:
        printResult(url, rtype, [], timeTaken)
    # print("MSG SIZE RCVD: ",sys.getsizeof(response))
    # print(response.payload)
    return timeTaken

#Funcs

root_servers = {} # Root servers and their ips

root_servers['a'] = '198.41.0.4'
root_servers['b'] = '199.9.14.201'
root_servers['c'] = '192.33.4.12'
root_servers['d'] = '199.7.91.13'
root_servers['e'] = '192.203.230.10'
root_servers['f'] = '192.5.5.241'
root_servers['g'] = '192.112.36.4'
root_servers['h'] = '198.97.190.53'
root_servers['i'] = '192.36.148.17'
root_servers['j'] = '192.58.128.30'
root_servers['k'] = '193.0.14.129'
root_servers['l'] = '199.7.83.42'
root_servers['n'] = '202.12.27.33'


inputString = input()
inputList = inputString.split()
if inputList[0] != "mydig":
    print("ERROR, Please enter mydig website rtype")
else:
    
    finalFunc(inputList[1], inputList[2]) # Calling the main function
    

