# -*- coding: utf-8 -*-
""" Module for PAN-OS communication

Module consist of two classes.
PanOsDevice - used for importing and installation on single device
Panorama- used when importing and installing to multiple devices through panorama
"""
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
from parse import XmlReader
from os import path
import os
import sys
import ssl
import pan.xapi
import logging
import urllib2
import traceback
import time

# Wait time out - timeout when waiting for complettion of install jobs on FW in seconds
waittimeout = 600

### Class for single PAN-OS Device


class PanOsDevice(object):

    PACKAGE = {
        "appthreat": "./panupv2-all-contents/",
        "app":       "./panupv2-all-apps/",
        "antivirus": "./panup-all-antivirus/",
        "wildfire":  "./panup-all-wildfire/",
        "wildfire2": "./panupv2-all-wildfire/",
        "wf500": "./panup-all-wfmeta/",
        }

    def __init__(self, hostname, apikey, name, timeout, verbose, package):
        # Need to set type to correct value for use in API call
        if package == "wildfire2": self.type = "wildfire"
        elif package == "app": self.type = "content"
        elif package == "appthreat": self.type = "content"
        else: self.type = package
        self.hostname = hostname
        self.username = None
        self.password = None
        self.name = name
        self.timeout = timeout
        self.apikey = apikey
        self.app_version = None
        self.threat_version = None
        self.av_version = None
        self.wf_version = None
        self.package = package
        self.path = self.PACKAGE[package]
        self.verbose = verbose
        self.panxapi = pan.xapi.PanXapi(hostname=hostname, api_key=apikey, timeout=timeout)

    def upload_to_device(self,file):
        # Compere version to install with version currently installed.
        install_version = file.split('-')
        install_version = install_version[3] + install_version [4]
        if self.package == 'appthreat': current_version = self.app_version.split('-')
        elif self.package == 'app': current_version = self.app_version.split('-')
        elif self.package == 'antivirus': current_version = self.av_version.split('-')
        elif self.package == 'wildfire': current_version = self.wf_version.split('-')
        elif self.package == 'wildfire2': current_version = self.wf_version.split('-')
        elif self.package == 'wf500': current_version = self.wf_version.split('-')
        else:
            print self.package, " is not a supported content type. Usage: push_updates.py -h"
            sys.exit()
        # Skip upload if current version is the same or newer
        if not current_version[0] == "0": #If version is 0, nothing is installed, and we want to continue
            current_version = current_version[0] + current_version[1]
            if current_version >= install_version:
                logging.info("Current version(%s) of %s is the same or newer than verison we tried to install(%s). Skipping upload for device %s" % (current_version,self.package,install_version, self.name))
                return False  # Return false to indicate file was noe uploaded.
        # Set filepath to update file location, and store current location
        currentdir = os.getcwd()
        os.chdir( self.path )
        # Build api url
        api_call = "https://%s/api/?type=import&category=%s&file-name=%s&key=%s" % (self.hostname, self.type, file, self.apikey)
        # Open File and upload it
        with open(file, 'r') as f:
            log_message = "%s file %s opened. Uploading to device.." % (self.package,file)
            logging.debug(log_message)
            log_message = "API request: %s" % (api_call)
            logging.debug(log_message)
            ctx = ssl._create_unverified_context()
            #opener = register_openers()
            ##### Need to find alternativ method...not recommended...!!!!
            #ssl._create_default_https_context = ssl._create_unverified_context
            #####
            # Use multipart_encode to encode file and generate headers.
            datagen, headers = multipart_encode({"file": f})
            # Open URL
            request = urllib2.Request(api_call, datagen, headers)
            try:
                response = urllib2.urlopen(request, context=ctx, timeout=self.timeout).read()
            except Exception:
                logging.error("Error while uploading %s to %s" % (file, self.hostname))
                logging.error(traceback.format_exc())
                if self.verbose:
                    log_message = "Error while uploading %s to %s" % (file, self.hostname)
                    if verbose: print log_message
                    logging.error(log_message)
                os.chdir( currentdir )
                f.close()
                return False  # Return false to indicate that upload failed
        f.close()
        os.chdir( currentdir )
        logging.debug("%s successfully uploaded to %s" % (file, self.name))
        return True  # Return true to indicate successfull upload


    def install_on_device(self,file,wait):
        if self.verbose: print "Starting install of %s on %s" % (file, self.name)
        xpath = "<request><%s><upgrade><install><file>%s</file></install></upgrade></%s></request>" % (self.type, file, self.type)
        # Timeout for while loop - used if wait is true
        whiletimeout = time.time() + waittimeout
        try:
            self.panxapi.op(xpath)
            result = self.panxapi.xml_root()
            # If wait is not set, return xml output
            if not wait : return result
            if self.verbose: print "Waiting for install job to complete on %s - will wait for max %s seconds" % (self.name, waittimeout)
            xmlreader = XmlReader(result)
            jobid = xmlreader.find_jobid()
        except:
            log_message = "Error running API command to install update on Panorama. Method 'install_to_panorama'"
            print log_message
            logging.error(log_message)
            sys.exit()
        cmd = 'show jobs id "%s"' % (jobid)
        while True:
            # cheks for completed job every 5 seconds
            time.sleep(5)
            self.panxapi.op(cmd=cmd, cmd_xml=True)
            output = self.panxapi.xml_result()
            xmlreader = XmlReader(output)
            status,progress = xmlreader.find_status()
            if self.verbose: print "Install job running on %s - Status : %s %s%%" % (self.name, status, progress)
            # when job statis is "FIN" - continue
            if status == "FIN":
                if self.verbose: print "Install job completed on %s." % (self.name)
                if self.type == "wildfire": return True  # No additional job started on wildfire install
                nextjobid = xmlreader.findnextjobid()
                # Monitor status of next job (content install job)
                while True:
                    # Check every 5 seconds
                    time.sleep(5)
                    cmd2 = 'show jobs id "%s"' % (nextjobid)
                    self.panxapi.op(cmd=cmd2, cmd_xml=True)
                    output2 = self.panxapi.xml_result()
                    xmlreader2 = XmlReader(output2)
                    status2,progress2 = xmlreader2.find_status()
                    if self.verbose: print "%s job is running on %s - Status: %s %s%%" % (type,self.name,status2,progress2)
                    # When status is FIN - job is completed successfully
                    if status2 == "FIN":
                        if self.verbose: print "%s job is done on %s" % (type, self.name)
                        return True
                    if time.time() > whiletimeout: return False  # Exits loop by returning false when timeout is reached for content install job
            if time.time() > whiletimeout: return False  # Exits loop by returning false when timeout is reached for first install job


    def check_installed_version(self):
        cmd = "show system info"
        self.panxapi.op(cmd=cmd,cmd_xml=True)
        output = self.panxapi.xml_root()
        reader = XmlReader(output)
        self.app_version,self.threat_version,self.av_version,self.wf_version = reader.find_content_versions()
