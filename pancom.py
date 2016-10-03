# -*- coding: utf-8 -*-
#Copyright (c) 2016 Data Equipment AS
#Author: Tor Mogstad <torm _AT_ dataequipment.no>

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

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


class UploadError(StandardError):
    pass

class InstallError(StandardError):
    pass

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
        elif package == "antivirus": self.type = "anti-virus"
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
        self.cert_verify = False
        self.panxapi = pan.xapi.PanXapi(hostname=hostname, api_key=apikey, timeout=timeout)
        if not self.cert_verify: self.context = ssl._create_unverified_context()
        else: self.context = ssl._create_default_https_context()


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
            # Use multipart_encode to encode file and generate headers.
            datagen, headers = multipart_encode({"file": f})
            data =str().join(datagen)  # Data must be a string
            # Generate request
            request = urllib2.Request(api_call, data, headers)
            try:
                response = urllib2.urlopen(request, context=self.context, timeout=self.timeout).read()
            except Exception as e:
                os.chdir( currentdir )
                f.close()
                raise UploadError(e)
        f.close()
        os.chdir( currentdir )
        logging.debug("%s successfully uploaded to %s" % (file, self.name))
        return True  # Return true to indicate successfull upload


    def install_on_device(self,file,wait):
        if self.verbose: print "Starting install of %s on %s" % (file, self.name)
        xpath = "<request><%s><upgrade><install><file>%s</file></install></upgrade></%s></request>" % (self.type, file, self.type)
        # Timeout for while loop - used if wait is true
        whiletimeout = time.time() + self.timeout
        try:
            self.panxapi.op(xpath)
            result = self.panxapi.xml_root()
            # If wait is not set, we are done. False returned to indicate we did not wait
            if not wait : return False
            if self.verbose: print "Waiting for install job to complete on %s - will wait for max %s seconds" % (self.name, self.timeout)
            xmlreader = XmlReader(result)
            jobid = xmlreader.find_jobid()
            cmd = 'show jobs id "%s"' % (jobid)
        except:
            log_message = "Error running API command to install update on Panorama"
            logging.error(log_message)
            logging.error(str(e))
            raise InstallError(log_message)
        while True:
            # cheks for completed job every 5 seconds. Exit if wait timeer is expired
            if time.time() > whiletimeout:
                log_message = "Timeout waiting for completetion of install job of %s on device %s. Command: %s" % (self.name, file, cmd)
                logging.error(log_message)
                raise InstallError(log_message)
            time.sleep(5)
            try:
                self.panxapi.op(cmd=cmd, cmd_xml=True)
                output = self.panxapi.xml_result()
            except Exception as e:
                logging.error(str(e))
                raise InstallError("Error when executing API call to find job status for firewall %s. Command: %s" % (self.name, cmd))
            try:
                xmlreader = XmlReader(output)
                status,progress = xmlreader.find_status()
            except:
                raise InstallError("Error when parsing xml output to find job status for device %s. Output: %s" % (self.name, output))
            if self.verbose: print "Install job running on %s - Status : %s %s%%" % (self.name, status, progress)
            # when job statis is "FIN" - continue
            if status == "FIN":
                if self.verbose: print "Install job completed on %s." % (self.name)
                try:
                    nextjobid = xmlreader.findnextjobid()
                except:
                    logging.info("Next job id not found when in response from job %s on fw %s. Installation succeeded." % (jobid, self.name))
                    return True # exception here means there is no new job started, and installation suceeded.
                # Monitor status of next job (content install job)
                while True:
                    cmd2 = 'show jobs id "%s"' % (nextjobid)
                    # cheks for completed job every 5 seconds. Exit if wait timeer is expired
                    if time.time() > whiletimeout:
                        log_message = "Timeout waiting for completetion of install job of %s on device %s. Command: %s" % (self.name, file, cmd2)
                        log.error(log_message)
                        raise InstallError(log_message)
                    time.sleep(5)
                    try:
                        self.panxapi.op(cmd=cmd2, cmd_xml=True)
                        output2 = self.panxapi.xml_result()
                    except Exception as e:
                        logging.error(str(e))
                        raise InstallError("Error when executing API call to find job status for firewall %s. Install job might not be necessary or failed. Command: %s" % (self.name, cmd2))
                    try:
                        xmlreader2 = XmlReader(output2)
                        status2,progress2 = xmlreader2.find_status()
                    except:
                        raise InstallError("Error when parsing xml output to find job status for device %s. Output: %s" % (self.name, output))
                    if self.verbose: print "%s job is running on %s - Status: %s %s%%" % (type,self.name,status2,progress2)
                    # When status is FIN - job is completed successfully
                    if status2 == "FIN":
                        if self.verbose: print "%s job is done on %s" % (type, self.name)
                        return True


    def check_installed_version(self):
        cmd = "show system info"
        try:
            self.panxapi.op(cmd=cmd,cmd_xml=True)
            output = self.panxapi.xml_root()
            reader = XmlReader(output)
            self.app_version,self.threat_version,self.av_version,self.wf_version = reader.find_content_versions()
            return True
        except pan.xapi.PanXapiError as e:
            raise UploadError(e)
