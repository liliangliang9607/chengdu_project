#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
reload(sys)
sys.setdefaultencoding("utf-8")

try: 
  import xml.etree.cElementTree as ET 
except ImportError: 
  import xml.etree.ElementTree as ET

import argparse
ns = {"ioc":"http://schemas.mandiant.com/2010/ioc",
      "xsd":"http://www.w3.org/2001/XMLSchema",
	  "xsi":"http://www.w3.org/2001/XMLSchema-instance"}

def main():
  arg_parser = argparse.ArgumentParser()
  arg_parser.add_argument('-iocnomd5', dest = 'iocnomd5',  help = 'Path to IOC no md5', default = '/opt/work/serverids/release/conf/ioc_rule_cloud.xml')
  arg_parser.add_argument('-iochs', dest = 'iochs',  help = 'Path to IOC hyperscan generated', default = '/opt/work/serverids/release/conf/ioc_rule_cloud.hs')
  args = arg_parser.parse_args()

  try:
    tree = ET.parse(args.iocnomd5)
    iocnomd5_root = tree.getroot()
  except Exception, e:
    print e
    print "Error: failed to parse xml file\n"

  try:
    fp = open(args.iochs, 'w')
    ioctree = ET.Element('IOCs')
    for iocnode in iocnomd5_root.findall("IOC"):
        ruleElem = iocnode.find('rule')
        rule = ruleElem.text
        line = iocnode.attrib['id'] + "||" + iocnode.attrib['type'] + "||" + rule
        fp.write(line[0:1022]+"\n")
    
    fp.close()
  except Exception, e:
    print e
    print "Error: processing xml file failed\n"
    print line

if __name__ == '__main__':
  main();
