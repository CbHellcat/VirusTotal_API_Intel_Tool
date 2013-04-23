## Information
Virus Total API Intelligence Report and Download Script v1.1

This script combines the funtions of Chris Clark's VT script and Emiliano Martinez's VT Intelligence Downloader script. You will be able to eaisly scan and hash a file, or file with a hash list. It can download malware, reports, pcaps, Json report, and rescan just like the orignal vt.py script. This script will allow all of those functions with the ability of using the VT Intelligence querying and bulk downloading provided by the VT Intelligence script. 
 
NOTE: You need your own premium VT API to use this tool. API Key Goes on Line 79!

## Required

Python 2.7

## Authors & Licence
Orginal Script Author: Chris Clark (vt.py), and Emiliano Martinez (vt_intelligence_downloader.py)

Rewirtten & Modified: Clay Batchelor

License: Do whatever you want with it :) 

## Example
<pre>
Usage is as follows with an example of a basic search and most of the switches: 

usage: vtintel.py [-h] [-d] [-v] [-r] [-j] [-p] [-f] Number Query

Search and download reports and files from VirusTotal

positional arguments:
  Number          Enter the number of downloads/reports to retrieve based on the query
  Query           Enter query for VT. This can be a hash, hash list, file to be hashed, or search expressions

optional arguments:
  -h, --help      show this help message and exit
  -d, --download  Number of files to download
  -v, --verbose   Verbose VT report(s)
  -r, --report    VT report(s) of submitted file(s)
  -j, --jsondump  Dumps full VT report to JSON file(s)
  -p, --pcap      Download network traffic capture for file(s)
  -f, --force     Force rescan of file(s) with current A/V definitions

Query Help:
    Windows: Quote queries with double quote, ""
    Other OS: Quote queries with either type, '' or ""

    Querying capabilities in depth: https://www.virustotal.com/intelligence/help/ 

Example Basic Query:

	clay@RE:~/Desktop/Python Files/Git$ python vtintel.py -rd 1 'type:peexe'

	Terminal Output: 
	Apr-23-13_17:35:49 INFO     Virus Total API Intelligence Report and Download Script v1.1
	Apr-23-13_17:35:49 INFO     Starting VirusTotal Search
	Apr-23-13_17:35:49 INFO     * VirusTotal Intelligence search: type:peexe
	Apr-23-13_17:35:49 INFO     * Number of files to retrieve for download/report: 1
	Apr-23-13_17:35:49 INFO     Creating folder to store the requested files
	Apr-23-13_17:35:49 INFO     Retrieving page of file hashes matching query
	Apr-23-13_17:35:51 INFO     Retrieved 25 matching files in current page
	Apr-23-13_17:35:51 INFO     Queued requested number of files for download/reporting
	Apr-23-13_17:35:51 INFO     Waiting for queued files to finish
	Apr-23-13_17:35:52 INFO     Downloading file 28ab5d4b206c3d57ca88d62df0f0c2a91b0fe600b005f2d5230cb2d170d0e793
	Apr-23-13_17:35:53 INFO     28ab5d4b206c3d57ca88d62df0f0c2a91b0fe600b005f2d5230cb2d170d0e793 download was successful
	Apr-23-13_17:35:59 INFO     The download/report files have been saved in ~Script Path~/VT_Files/Apr-23-13_17:35:49

	Directory Created: 
	drwxrwxr-x 3   4096 Apr 23 17:35 VT_Files
	-rw-r--r-- 1  12226 Apr 23 17:30 vtintel.py

	VT_Files:
	drwxrwxr-x 2  4096 Apr 23 17:35 2013-04-18_16-31-29

	Apr-23-13_17:35:49 Directory:
	-rw-rw-r-- 1  31232 Apr 23 17:35 28ab5d4b206c3d57ca88d62df0f0c2a91b0fe600b005f2d5230cb2d170d0e793._Win32 EXE_
	-rw-rw-r-- 1    592 Apr 23 17:35 28ab5d4b206c3d57ca88d62df0f0c2a91b0fe600b005f2d5230cb2d170d0e793_Report.txt
	-rw-rw-r-- 1     10 Apr 23 17:35 VT-Query.txt

	The file name is the sha256 of the file with the filetype from the json report as the extension. The report is named sha256_Report.txt. The query used to retrieve the files and reports can be found within the VT-Query.txt file. 


Example Advanced Query:

	clay@RE:~/Desktop/Python Files/Git$ python vtintel.py -dvjp 3 'type:peexe AND sources:5 AND positives:20+'

	Terminal Output:

	Apr-18-13_16:58:13 INFO     Starting VirusTotal Search
	Apr-18-13_16:58:13 INFO     * VirusTotal Intelligence search: type:peexe AND sources:5 AND positives:20+
	Apr-18-13_16:58:13 INFO     * Number of files to retrieve for download/report: 3
	Apr-18-13_16:58:13 INFO     Creating folder to store the requested files
	Apr-18-13_16:58:13 INFO     Retrieving page of file hashes matching query
	Apr-18-13_16:58:14 INFO     Retrieved 25 matching files in current page
	Apr-18-13_16:58:14 INFO     Queued requested number of files for download/reporting
	Apr-18-13_16:58:14 INFO     Waiting for queued files to finish
	Apr-18-13_16:58:17 INFO     Downloading file ac859b6fb97bd77931817080494db853a1ce03ed011b058ceddcda02abd10707
	Apr-18-13_16:58:20 INFO     ac859b6fb97bd77931817080494db853a1ce03ed011b058ceddcda02abd10707 download was successful
	Apr-18-13_16:58:31 INFO     Downloading file cbdffeb0ea5fb01e13ab85e7d8a5694873713b8fc61225b5dae9363189b7aac6
	Apr-18-13_16:58:32 INFO     cbdffeb0ea5fb01e13ab85e7d8a5694873713b8fc61225b5dae9363189b7aac6 download was successful
	Apr-18-13_16:58:40 INFO     Downloading file ce3467195c466b52ce46469c1b4031105bfc65d2f259bdc2d20e934db561be0d
	Apr-18-13_16:58:41 INFO     ce3467195c466b52ce46469c1b4031105bfc65d2f259bdc2d20e934db561be0d download was successful
	Apr-18-13_16:58:41 INFO     The download/report files have been saved in ~Script Path~/VT_Files/Apr-18-13__16-58-13

	2013-04-18_16-58-13 Directory:
	
	-rw-rw-r-- 1     22272 Apr 18 16:58 ac859b6fb97bd77931817080494db853a1ce03ed011b058ceddcda02abd10707_Behavior.txt
	-rw-rw-r-- 1    248504 Apr 18 16:58 ac859b6fb97bd77931817080494db853a1ce03ed011b058ceddcda02abd10707._Win32 EXE_
	-rw-rw-r-- 1     54356 Apr 18 16:58 ac859b6fb97bd77931817080494db853a1ce03ed011b058ceddcda02abd10707.json
	-rw-rw-r-- 1    183947 Apr 18 16:58 ac859b6fb97bd77931817080494db853a1ce03ed011b058ceddcda02abd10707.pcap
	-rw-rw-r-- 1     15163 Apr 18 16:58 ac859b6fb97bd77931817080494db853a1ce03ed011b058ceddcda02abd10707_Report.txt
	-rw-rw-r-- 1     47568 Apr 18 16:58 cbdffeb0ea5fb01e13ab85e7d8a5694873713b8fc61225b5dae9363189b7aac6_Behavior.txt
	-rw-rw-r-- 1     69568 Apr 18 16:58 cbdffeb0ea5fb01e13ab85e7d8a5694873713b8fc61225b5dae9363189b7aac6._Win32 EXE_
	-rw-rw-r-- 1    100365 Apr 18 16:58 cbdffeb0ea5fb01e13ab85e7d8a5694873713b8fc61225b5dae9363189b7aac6.json
	-rw-rw-r-- 1  17717512 Apr 18 16:58 cbdffeb0ea5fb01e13ab85e7d8a5694873713b8fc61225b5dae9363189b7aac6.pcap
	-rw-rw-r-- 1     18023 Apr 18 16:58 cbdffeb0ea5fb01e13ab85e7d8a5694873713b8fc61225b5dae9363189b7aac6_Report.txt
	-rw-rw-r-- 1     44189 Apr 18 16:58 ce3467195c466b52ce46469c1b4031105bfc65d2f259bdc2d20e934db561be0d_Behavior.txt
	-rw-rw-r-- 1     61376 Apr 18 16:58 ce3467195c466b52ce46469c1b4031105bfc65d2f259bdc2d20e934db561be0d._Win32 EXE_
	-rw-rw-r-- 1     93905 Apr 18 16:58 ce3467195c466b52ce46469c1b4031105bfc65d2f259bdc2d20e934db561be0d.json
	-rw-rw-r-- 1  33217906 Apr 18 16:58 ce3467195c466b52ce46469c1b4031105bfc65d2f259bdc2d20e934db561be0d.pcap
	-rw-rw-r-- 1     17162 Apr 18 16:58 ce3467195c466b52ce46469c1b4031105bfc65d2f259bdc2d20e934db561be0d_Report.txt
	-rw-rw-r-- 1        42 Apr 18 16:58 VT-Query.txt

Example File Search:

	clay@RE:~/Desktop/Python Files/Git$ python vtintel.py -r 1 '/home/clay/Desktop/Python Files/test.txt' 

	Apr-18-13_17:07:43 INFO     Starting VirusTotal Search
	Apr-18-13_17:07:43 INFO     * VirusTotal Intelligence search: 49F8E63F56BF1E8BD3495597BF343A0B
	Apr-18-13_17:07:43 INFO     * Number of files to retrieve for download/report: 1
	Apr-18-13_17:07:43 INFO     Creating folder to store the requested files
	Apr-18-13_17:07:43 INFO     Retrieving page of file hashes matching query
	Apr-18-13_17:07:46 INFO     No more matching files
	Apr-18-13_17:07:46 INFO     Waiting for queued files to finish
	Apr-18-13_17:07:49 INFO     The download/report files have been saved in ~Script Path~/VT_Files/Apr-18-13_17-07-43

	File is hashed (md5) and used as query. If there are no matching files in the VT database then only the query file will be created in the folder. 

Example Hash List Search:

	clay@RE:~/Desktop/Python Files/Git$ python vtintel.py -r 3 '/home/clay/Desktop/Python Files/hashlist.txt' 

	Apr-18-13_17:11:57 INFO     Starting VirusTotal Search
	Apr-18-13_17:11:57 INFO     * VirusTotal Intelligence search: 9e08913280316ca908e285fd4d2d039a,91f13a33f7ada53ce06541459ae89331,6765f66e39c6c3b1c5cf17565fa86ff4
	Apr-18-13_17:11:57 INFO     * Number of files to retrieve for download/report: 3
	Apr-18-13_17:11:57 INFO     Creating folder to store the requested files
	Apr-18-13_17:11:57 INFO     Retrieving page of file hashes matching query
	Apr-18-13_17:11:59 INFO     Retrieved 3 matching files in current page
	Apr-18-13_17:11:59 INFO     Queued requested number of files for download/reporting
	Apr-18-13_17:11:59 INFO     No more matching files
	Apr-18-13_17:11:59 INFO     Waiting for queued files to finish
	Apr-18-13_17:12:06 INFO     The download/report files have been saved in ~Script Path~/VT_Files/Apr-18-13_17-11-57
	
	2013-04-18_17-11-57 Directory:
	-rw-rw-r--  1   634 Apr 18 17:12 a1af6fd1a8bea85a19b271d0905eb8a4ba58ed01ca2477a4b22141df372f861b_Report.txt
	-rw-rw-r--  1   662 Apr 18 17:11 cbdffeb0ea5fb01e13ab85e7d8a5694873713b8fc61225b5dae9363189b7aac6_Report.txt
	-rw-rw-r--  1   589 Apr 18 17:11 ce3467195c466b52ce46469c1b4031105bfc65d2f259bdc2d20e934db561be0d_Report.txt
	-rw-rw-r--  1    98 Apr 18 17:11 VT-Query.txt


</pre>

## Example Reports Added

Report.txt
Verbose.txt
Behavior.txt
VT_JSON_Example.json

## Todo
  
Clean up code, indentation and quote unformity
Clean up/change terminal output
Fix some spacing issues in reports
Add function to avoid downloading files/reports that have already been downloaded
