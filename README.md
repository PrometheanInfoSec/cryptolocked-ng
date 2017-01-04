#Cryptolocked

Cryptolocked is an anti-ransomware toolkit.

Features:
* Tentacles Module (file integrity monitoring)
* Failsafe shuts down system upon IOC
* Email alerts
* Sensitive Alerting
* Hunter Module kills all processes that access certain file handles


Files:
* cl.conf --> Configuration file
* cryptolocked-ng.py --> Main script (executable)
* hunter.lst --> File containing list of file handles for hunter to monitor
* README.md --> This readme file
* tentacles.lst --> File containing list of files for tentacles to monitor

