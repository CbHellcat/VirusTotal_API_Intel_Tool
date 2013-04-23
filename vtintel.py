#!/usr/bin/python
# Virus Total API Intelligence Report and Download Script
# Version = 1.1
# Built on VT API Script from Chris Clark and VT Downloader script from Emiliano Martinez.
# Rewirtten / Modified / Personalized: Clay Batchelor ~ GD Fidelis CyberSecurity
# Use however you want to! 
#
#TODO:  Clean up code, indentation and quote unformity
#       Clean up/change terminal output
#       Fix some spacing issues in reports
#       Add function to avoid downloading files/reports that have already been downloaded
#
'''
This script combines the funtions of Chris Clark's VT script and Emiliano Martinez's VT Intelligence Downloader script. It can be used with Python 2.7. 
 
If you do not have a Private API key that allows access to Intelligence searching, downloading, and reports, then this 
script will not function properly. 
'''
import json, logging, argparse, os, Queue, re, socket, sys, threading, urllib, urllib2, hashlib, codecs
from pprint import pprint
from time import sleep
from datetime import datetime
from collections import OrderedDict

__VERSION__ = "1.1"

Current_Downloads = 5

socket.setdefaulttimeout(10)

LOGGING_LEVEL = logging.INFO
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%b-%d-%y_%H:%M:%S',
                    stream=sys.stdout)


class Error(Exception):
  """Base-class for exceptions in this module."""

class InvalidQueryError(Error):
  """Search query is not valid."""


def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else: 
    return checkval.upper()


def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest() 


def downloadFolder(query=None):
  folder_path = os.path.join(os.getcwd(), 'VT_Files', datetime.now().strftime('%b-%d-%y_%H:%M:%S'))
  try:
    os.makedirs(folder_path)
  except OSError, e:
    if e.errno != 17:
      raise
  query_path = os.path.join(folder_path, 'VT-Query.txt') #
  with open(query_path, 'wb') as query_file:
    query_file.write(query)
  return folder_path        


class vtAPI():
    def __init__(self):
        self.api = ''
        self.search = ('https://www.virustotal.com/intelligence/search/'
                           'programmatic/')
        self.download = ('https://www.virustotal.com/intelligence/download/'
                             '?hash=%s&apikey=%s')     
        self.report = 'https://www.virustotal.com/vtapi/v2/'

            
    def getMatchingFiles(self,query,page=None):
      response = None
      page = page or 'undefined'
      attempts = 0
      param = {'query': query, 'apikey': self.api, 'page': page}
      data = urllib.urlencode(param)
      req = urllib2.Request(self.search, data)
      while attempts < 3:
        try:
          response = urllib2.urlopen(req).read()
          break
        except Exception:
          attempts += 1
          sleep(1)
      if not response:
        return (None, None)        
        
      try:
        response_dict = json.loads(response)
      except ValueError:
        return (None, None)
    
      if not response_dict.get('result'):
        raise InvalidQueryError(response_dict.get('error'))
    
      next_page = response_dict.get('next_page')
      hashes = response_dict.get('hashes', [])
      return (next_page, hashes)        


    def getReport(self,sha256):
        param = {'resource':sha256,'apikey':self.api,'allinfo': '1'}
        url = self.report + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        return jdata


    def downloadFile(self,sha256,name):
      try:
        param = {'hash':sha256,'apikey':self.api}
        url = self.download % (sha256, self.api)
        data = urllib.urlencode(param)
        req = urllib2.Request(url,data)
        result = urllib2.urlopen(req)
        downloadedfile = result.read()
        if len(downloadedfile) > 0:
          fo = open(name,"w")
          fo.write(downloadedfile)
          fo.close()
          return True
        else:
          return False
      except Exception:
          return False


    def downloadPcap(self,sha256,name):
      try:
        req = urllib2.Request("https://www.virustotal.com/vtapi/v2/file/network-traffic?apikey="+self.api+"&hash="+sha256)
        result = urllib2.urlopen(req)
        pcapfile = result.read()
        if len(pcapfile) > 0 and '{"response_code": 0, "hash":' not in pcapfile :
          fo = open(name,"w")
          fo.write(pcapfile)
          fo.close()
          return True
        else:
          return False
      except Exception:
          return False


    def rescan(self,sha256):
        param = {'resource':sha256,'apikey':self.api}
        url = self.report + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        logging.info("\n\tVirus Total Rescan Initiated for -- " + sha256 + " (Requery in 10 Mins)")

        
    def parser(self, dictionary, indent=False):
        dictionary = OrderedDict(sorted(dictionary.items(), key=lambda t: t[0]))
        for k, v in dictionary.iteritems():
            if isinstance(v, dict):
                yield '\n\t%s: ' %k
                for value in self.parser(v, True):
                    yield value
            else:
                if indent:
                    tab = '\t'
                else:
                    tab = ''
                if isinstance(v, list):
                    c = 0
                    if tab == '':
                        tab = '\n\t'
                    yield '%s%s:' % (tab, k)                    
                    for nested in v:
                        c += 1
                        if isinstance(nested, unicode):
                            yield '\t\t%s' % nested           
                            if c == len(v): yield '\n'        
                        else:
                            if isinstance(nested, dict):
                                for nestdict in self.parser(nested, True):
                                    yield '\t' + nestdict
                            else:        
                                yield '\t%s: ' % ','.join(map(str, nested)) 
                          
                else:
                    yield "%s%s: %s"%(tab,k,v)


def report(raw, sha256, verbose, jsondump, reportname):
  if raw["response_code"] == 0:
    logging.info(sha256 + ' -- Not Found in VT')
    return 0
  vt = vtAPI()
  output = list()
  output.append('=================================\n')
  output.append('VirusTotal Report for %s' % sha256)
  output.append('\n=================================\n')
  output.append('MD5: %s' % raw['md5']) 
  output.append('SHA1: %s' % raw['sha1']) 
  output.append('SHA256: %s\n' % raw['sha256']) 
  output.append('Detected by: %s/%s' % (raw['positives'], raw['total']))
  try:  
    output.append('Kaspersky Detection: %s' % raw['scans']['Kaspersky']['result'])
  except KeyError:
    output.append('Kaspersky Detection: None')  
  output.append('Scanned On: %s' % raw['scan_date'])
  output.append('First Seen: %s' % raw['first_seen'])
  output.append('Last Seen: %s' % raw['last_seen'])
  output.append('Unique Sources: %s' % raw['unique_sources'])
  output.append('File Tags: %s' % ', '.join(map(str, raw['tags'])))
  output.append('File Type: %s' % raw['type'])
  output.append('File Size: %s' % raw['size'])
  output.append('Submission Names:')
  for x in raw['submission_names']:
    output.append('\t%s' % x) 

  if jsondump == True:
    jsondumpfile = codecs.open(reportname + '.json', 'w', encoding='utf-8')
    pprint(raw, jsondumpfile)
    jsondumpfile.close()

  if verbose == True:
      output.append('\n=================================\n')
      output.append('VirusTotal Verbose Report')
      output.append('\n=================================\n')
      output.append('Additional File Information:')
      output.append('----------------------------\n')
      for line in raw['additional_info'].keys():
          if line == 'behaviour-v1':
              behavior = list()
              behavior.append('=================================\n')
              behavior.append('VirusTotal Behavior Report for %s' % sha256)
              behavior.append('\n=================================\n')
              for parsed_data in vt.parser(raw['additional_info']['behaviour-v1']):
                  behavior.append('\t%s' % parsed_data)
              codecs.open(reportname + '_Behavior.txt', 'w', encoding='utf-8').write('\n'.join(behavior))
              del raw['additional_info']['behaviour-v1']    
      for parsed_data in vt.parser(raw['additional_info']):
          output.append('\t%s' % parsed_data)
      output.append('\n--------------------')
      output.append('AV Scan Information:')             
      output.append('--------------------\n')    
      for parsed_data in vt.parser(raw['scans']):
          output.append('\t%s' % parsed_data)       
  codecs.open(reportname + '_Report.txt', 'w', encoding='utf-8').write('\n'.join(output))

    
def main():
  opt=argparse.ArgumentParser(
      prog='vtintel.py', 
      formatter_class=argparse.RawDescriptionHelpFormatter,
      description='Search and download reports and files from VirusTotal',
      epilog=('''\
Query Help:  
    Windows: Quote queries with double quote, ""
    Other OS: Quote queries with either type, '' or ""

    Querying capabilities in depth: https://www.virustotal.com/intelligence/help/ 

Example Commands:
    vtintel.py -rdp 1 'type:peexe'
     #Download the report, pcap, and file for the first 2 files 
     that have the portable executable type 

    vtintel.py -d 100 C:\Malware_Hashes\April2013_Malware_Hashes.txt
     # Download 100 of the first files found to match 
     the hashes within the the provided text document'''))

  opt.add_argument('Number', default=0, help='Enter the number of downloads/reports to retrieve based on the query')      
  opt.add_argument('Query', help='Enter query for VT. This can be a hash, hash list, file to be hashed, or search expressions')
  opt.add_argument('-d', '--download', action='store_true', help='Number of files to download')
  opt.add_argument('-v', '--verbose', action='store_true', help='Verbose VT report(s)')
  opt.add_argument('-r', '--report', action='store_true', help='VT report(s) of submitted file(s)')
  opt.add_argument('-j', '--jsondump', action='store_true', help='Dumps full VT report to JSON file(s)')
  opt.add_argument('-p', '--pcap', action='store_true', help='Download network traffic capture for file(s)')
  opt.add_argument('-f', '--force', action='store_true', help='Force rescan of file(s) with current A/V definitions')
  
  if len(sys.argv)<=3:
    opt.print_help()
    sys.exit(1)
  options = opt.parse_args()
  
  end_process = False
  download = int(options.Number)
  
  if os.path.exists(options.Query):
    with open(options.Query, 'rb') as file_with_hashes:
      content = file_with_hashes.read()
      requested_hashes = re.findall(
          '([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})', content)
      if requested_hashes == []:
        filesearch = checkMD5(options.Query) #sha256 is the md5 of the provided file. 
        options.Query = filesearch
      else: 
        options.Query = ','.join(set(requested_hashes))
  
  vt=vtAPI()
  
  logging.info('Virus Total API Intelligence Report and Download Script v%s' % __VERSION__)
  logging.info('Starting VirusTotal Search')
  logging.info('* VirusTotal Intelligence search: %s', options.Query)
  logging.info('* Number of files to retrieve for download/report: %s', options.Number)

  work = Queue.Queue()  # Queues files to download
  end_process = False
  
  def worker():
    while not end_process:
      try:
        sha256, folder = work.get(True, 3)
        rawreport = vt.getReport(sha256) 
      except Queue.Empty:
        continue
      if options.report or options.jsondump or options.verbose:
        reportname = os.path.join(folder, sha256)
        report(rawreport, sha256 ,options.verbose, options.jsondump, reportname)
      if options.pcap:
        name = os.path.join(folder, sha256 + '.pcap')
        vt.downloadPcap(sha256,name)
      if options.force:
        vt.rescan(sha256)
      if options.download:
        destination_file = os.path.join(folder, sha256 + '._' + rawreport['type'] + '_')
        logging.info('Downloading file %s', sha256)
        success = vt.downloadFile(sha256, destination_file)
        if success:
          logging.info('%s download was successful', sha256)
        else:
          logging.info('%s download failed', sha256)
        work.task_done()
  
  threads = []
  for unused_index in range(Current_Downloads):
    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()
    threads.append(thread)
  
  logging.info('Creating folder to store the requested files')
  folder = downloadFolder(options.Query)
  
  queued = 0
  wait = False
  next_page = None
  while not end_process:
    try:
      logging.info('Retrieving page of file hashes matching query')
      try:
        next_page, hashes = vt.getMatchingFiles(options.Query, page=next_page)
      except InvalidQueryError, e:
        logging.info('The search query provided is invalid... %s', e)
        return
      if hashes:
        logging.info(
            'Retrieved %s matching files in current page',
            len(hashes))
      for file_hash in hashes:
        work.put([file_hash, folder])
        queued += 1
        if queued >= download:
          logging.info('Queued requested number of files for download/reporting')
          wait = True
          break
      if not next_page or not hashes:
        logging.info('No more matching files')
        wait = True
      if wait:
        logging.info('Waiting for queued files to finish')
        while work.qsize() > 0:
          sleep(5)
        end_process = True
        for thread in threads:
          if thread.is_alive():
            thread.join()
        logging.info('The download/report files have been saved in %s', folder)
    except KeyboardInterrupt:
      end_process = True
      logging.info('Stopping the download/report, initiated downloads must finish')
      for thread in threads:
        if thread.is_alive():
          thread.join()
  
if __name__ == '__main__':
    main()
