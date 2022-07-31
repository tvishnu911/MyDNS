import dns
import dns.resolver
import time
import sys

root_hash=["49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5".lower(),"E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D".lower()] # Root hash





def fetchResponseWithValidation(url, dnsDomain, rtype, root): # Used to make a call and check if the response is valid
#     print("Root check: ", root)
#     print("URL: ", url)
#     print("Root: ", root)
    response = fetchResponse(url, rtype, root) # Used to make a call and get response
#     print("DNS Domain: ", dnsDomain)
#     print("Root: ", root)
    responseDns = fetchResponse(dnsDomain, "DNSKEY", root)
    responseForValidation = validateDnsSec(response, responseDns, dnsDomain) # To validate the response
    if not responseForValidation:
        print("DNSSEC FAILED at DNS Domain: ", dnsDomain)
        return response, False        
    else:
        print("DNS Valid at ",dnsDomain)
        return response, True
def fetchNameServerIpWithValidation(ns, rtype, dnscount = 0, root = "198.41.0.4"): # Fetch the IP for name server, and validate the responses in the cycle
    global root_hash
    dnsdomain = "."
    response, response1 = fetchResponseWithValidation(ns, dnsdomain, rtype, root)
    if not response1:
#         print("Dns Failed")
        return False, False
    root_hash.append(response.authority[1].to_text().split(" ")[7])
    while not response.answer:
        nextIp = None
        for i in response.additional:
            if i.rdtype == 1:
                nextIp = str(i[0])
                break
        if not nextIp:
            return False, False
        dnscount += 1 # We increase the counter to determine the iteration to determine dnsdomain
        urlList = ns.split(".")
        if urlList[-1] == "":
            urlList.pop(-1)
        dnsdomain = ".".join(urlList[-dnscount:]) + "." # Update DNSdomain
        
#         print("urllist: ", urlList[-1] == "")
        root = nextIp
        response, response1 = fetchResponseWithValidation(ns, dnsdomain, rtype, root)
        if not response1:
#             print("Dns Failed")
            return False, False
    for i in response.answer:
        if i.rdtype == 1:
            return response.answer
    return False


#Funcs
def fetchResponse(queryText, rtype, targetIp): # Make a request and get response
    query = dns.message.make_query(queryText, rtype, want_dnssec=True)  
    response = dns.query.udp(query, targetIp, timeout = 2)
    return response

def ipsIn(result): # Check if A record in resultset
    for i in result:
        if i.rdtype == 1:
            return True
    return False
def nssIn(result):# Check if NS record in resultset
    for i in result:
        if i.rdtype == 2:
            return True
    return False
def mxsIn(result): # Check if MX record in resultset
    for i in result:
        if i.rdtype == 15:
            return True
    return False

def printResult(url, rType, resultSet, timeTaken): # To print the output formatted in 'dig' format
    print("QUESTION SECTION:")
    print("{}     IN      {}".format(url, rType))
    
    print("ANSWER SECTION:")
    print(resultSet[0])
    print("")
    print("Query time: {} msec".format(int(timeTaken)))
    print("When: {}".format(time.ctime()))
    print("MSG SIZE rcvd:", sys.getsizeof(resultSet))

def mainFunction(url, rType, dnsDomain = ".", dnsCounter = 0): # This is the function where the calls are made
    # print("URL: ", url)
    for root in root_servers.values():
        try:
            global root_hash
            dnsDomain = "."
            response, response1 = fetchResponseWithValidation(url, dnsDomain, rType, root)
#             print("Hash appending")
            root_hash.append(response.authority[1].to_text().split(" ")[7])
#             print("Hash appended")
            if not response1:
#                 print("DNSSEC FAILED")
                return False, False
            dnsCounter += 1
            urlList = url.split(".")
            if urlList[-1] == "":
                urlList.pop(-1)
            dnsDomain = ".".join(urlList[-dnsCounter:]) + "." # Updating the dnsDomain for next call
#             print(response) 
            while not response.answer:
#                 print(response)
                if response.additional:
                    for val in response.additional:
    #                     print(val)
                        if val.rdtype == 1:
                            nextIp = str(val[0])
#                             response = fetchResponse(url, rType, nextIp)
                            response, response1 = fetchResponseWithValidation(url, dnsDomain, rType, nextIp)
                            if response.answer:
                                break
                            if not response1:
#                                 print("DNSSEC FAILED")
                                return False, False
#                             print("Hash appending")
                            root_hash.append(response.authority[1].to_text().split(" ")[7])
#                             print("Hash appended")
                            dnsCounter += 1
                            urlList = url.split(".")
                            if urlList[-1] == "":
                                urlList.pop(-1)
                            dnsDomain = ".".join(urlList[-dnsCounter:]) + "."
                            break

                else:
                    if response.authority:
                        for val in response.authority:
                            if val.rdtype == 2:
                                nameServer = str(val[0])
                                break
#                         nameServerResponse = mainFunction(nameServer, "A")
                        nameServerResponseAnswer = fetchNameServerIpWithValidation(nameServer, "A") # Resolving name server
                        
#                         print(nameServerResponse)
    #                     return
                        for i in nameServerResponseAnswer:
                            foundNs = False
                            if i.rdtype == 1:
                                nextIp = i
#                                 print(nextIp)
                                response.additional = [nextIp]
                                foundNs = True
                                break
                        if not foundNs:
                            return response, True
                        # If there is no name server as well, the authority section might contain the NS. Check dig www.google.com NS
            if nssIn(response.answer) and rType == "NS": # If required type is NS and we got it, return
                return response, True
            if mxsIn(response.answer) and rType == "MX":# If required type is MX and we got it, return
                return response, True
            if ipsIn(response.answer): # If required type is A and we got it, return
                return response, True
            else:
#                 print("NO IPS")
                cname = None
                for i in response.answer:
                    if i.rdtype == 5:
#                         print("Has CNAMES")
                        cname = str(i)
                        
                        break
                if cname:
#                     print("In loop")
                    response1, response2 = mainFunction(str(i), rType)
#                     print(response1)
                    return (response1, True)
                else:
                    return response, True
#                     break
#                 return response
        except Exception as e:
            print(e)
            continue
        

def validateDnsSec(response1, response2, qtext): # Function to validate the responses
    
    
    
    global root_hash # The root hsah where the hashes of top level domains are stored
    ds = None
    rrsig = None
    if response1.answer:

        print("Keys are valid at ", qtext)
        print("Records are valid at ", qtext)
        
        return True

#     print("response1: ", response1)
    response2Dnskey = response2.answer[0]
#     response2Rrsig = response2.answer[1]
    for res in response2Dnskey:
#     print(res.rdtype)
        if "257" in str(res):
            zsk = res
            break
#     encryption_key=response.answer[0].to_text().split(" ")[6]
    
    
    zskDecrypt = dns.dnssec.make_ds(qtext, zsk, "SHA256", origin=None)
    zskDecrypt = str(zskDecrypt)
#     print("ZSK:", zskDecrypt)
#     print(zskDecrypt.split(" ")[3])
    zskDecrypt = (zskDecrypt.split(" ")[3])
#     print("ZSK: ", zskDecrypt)
    
    if not str(zskDecrypt) in root_hash: # Checking if zsk is in the root_hash for top levels
        print("ZSK not in hash!!".upper())
        print("DNSSEC Validation Failed!")
        return False
    else:
        print("ZSK valid")
        key=dns.name.from_text(qtext)
    try:
        if not dns.dnssec.validate(response2.answer[0], response2.answer[1], {key:response2.answer[0]}):
            print("Keys are valid at ", qtext)
        else:
            print("Keys are invalid at ", qtext)
            return False
    except Exception as e:
        print("Validation Failed!")
    try:
        if not dns.dnssec.validate(response1.authority[1], response1.authority[2], {key:response2.answer[0]}):
            print("Records are valid at ", qtext)
        else:
            print("Records are invalid at ", qtext)
            return False
    except Exception as e:
        print("DNSSEC Validation Failed!")
        return False
#     print("DNSSEC VALIDATED at \"{}\"".format(qtext))
    return True

def finalFunc(url, rtype): #Function used to call the main function
    startTime = time.time()
    finalUrl = url[::]
    # if url[:4] == "www.":
    #     finalUrl = finalUrl[4::]
    response, dns = mainFunction(finalUrl, rtype)
    
    print("Final response:\n")
    if not dns:
        print("**"*5)
        print("DNSSEC FAILED")
        print("**"*5)
        return
    print("**"*5)
    print("DNSSEC VALIDATED")
    print("**"*5)
#     print(response.answer)
    timeTaken = (time.time() - startTime)*10**3
    printResult(url, rtype, response.answer, timeTaken)
    return timeTaken

#Funcs

root_servers = {}

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


inputString = input() # Input 
inputList = inputString.split()
if inputList[0] != "mydig":
    print("ERROR, Please enter 'mydig [website] [rtype]'")
else:
    
    finalFunc(inputList[1], inputList[2])
# mydig www.google.com A
# mydig www.google.co.jp A
# mydig www.stonybrook.edu NS
# mydig www.dnssec-fail.org A
# mydig www.paypal.com MX