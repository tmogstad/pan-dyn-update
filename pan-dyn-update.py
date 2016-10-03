#!/usr/bin/env python

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




"""Install dynamic updates on Palo Alto Networks firewalls and Panorama

Checks and finds for newest update file in subfolders panupv2-all-apps,
panupv2-all-contents,panup-all-antivirus, panup-all-wfmeta, panupv2-all-wildfire
and panup-all-wildfire. Installs latest update on devices defined in devices.conf.

This software is provided without support, warranty, or guarantee.
Use at your own risk.

"""

from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
from pancom import PanOsDevice
from pancom import UploadError
from pancom import InstallError
from parse import EmailSender
import glob
import sys
import time
import os
from os import path
import argparse
import logging
import traceback

##### Static variables used in script - change only if needed
CONFIG_FILE = "config.conf"  # Config file
DEVICES_FILE = "devices.conf"  # Devices file
LOG_FILE = "log.txt"  # Log file used by script
# API timeout - also used when waiting for install job completion.
API_TIMEOUT = 300 #For devices like PA-200/PA-500 this value needs to be increased.

# List of supported content types
PACKAGE = {
    "appthreat": "panupv2-all-contents/",
    "app":       "panupv2-all-apps/",
    "antivirus": "panup-all-antivirus/",
    "wildfire":  "panup-all-wildfire/",
    "wildfire2": "panupv2-all-wildfire/",
    "wf500": "panup-all-wfmeta/",
}
# Supported logleves
LOGLEVELS = {
		"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
}

class FileError(StandardError):
    pass

class ApiKeyException(StandardError):
    pass

def find_newest_file(package):
    try:
        #Search for files in subdirectory under SCRIPT_PATH
        searchpath = PACKAGE[package] + "*"
        newest=max(glob.iglob(searchpath), key=os.path.getctime)
        #Remove path from filename and return it
        filename = newest.split('/')[-1]
        return filename
    except Exception as e:
        log_message = """Error checking for newest content file. Check if directorys ./panupv2-all-contents, ./panupv2-all-apps,
                        ./panupv2-all-apps, ./panup-all-wildfire, panupv2-all-wildfire  and ./panupv2-all-wildfire exists, and that files exits"""
        logging.error(log_message)
        logging.error(traceback.format_exc())
        raise FileError(e)


def get_passed_arguments():
    parser = argparse.ArgumentParser(description='Upload and install dynamic updates on Palo Alto Networks devices.')
    parser.add_argument('-l', '--loglevel', help="Set loglevel. Options: DEBUG, INFO, WARNING, ERROR or CRITICAL. Defaults to INFO")
    parser.add_argument('-t', '--type', help="Set content type. Must be <appthreat/app/antivirus/wildfire/wildfire2/wf500", required=True)
    parser.add_argument('-w', action='store_true', help="When set, script wait for install job to complete on devices, and reports status")
    parser.add_argument('-e', action='store_true', help="When set, email is sent with status of install jobs.")
    parser.add_argument('-v', action='store_true', help="Verbose mode. Prints status messages to prompt")
    return parser.parse_args()


def parse_config_file(email,verbose):
    apikey = None
    smtpuser = None
    smtppass = None
    smtpreceivers = []
    try:
        object = open(CONFIG_FILE, "r")
    except Exception as e:
        logging.error("Error opening config file")
        logging.error(traceback.format_exc())
        raise FileError(e)
    for i, line in enumerate(object):
        if not line.startswith("#"):
            type = line.split('=',1)[-2]
            value = line.split('=',1)[-1]
            if type == "apikey": apikey = value.rstrip()
            elif type == "smtphost": smtphost = value.rstrip()
            elif type == "smtpport": smtpport = value.rstrip()
            elif type == "smtpsender": smtpsender = value.rstrip()
            elif type == "smtpreceiver": smtpreceivers.append(value.rstrip())
            elif type == "smtpuser": smtpuser = value.rstrip()
            elif type == "smtppass": smtppass = value.rstrip()
            else:
                log_message = "Error parsing config file at line %s" % (line.rstrip())
                logging.error(log_message)
                raise FileError(log_message)
    object.close()
    if email:
        emailobj = EmailSender(smtpsender, smtpreceivers, smtphost, smtpport)
        if smtpuser is not None:
            emailobj.smtpuser = smtpuser
            emailobj.smtppass = smtppass
    else: emailobj = None
    if apikey is None: raise ApiKeyException("No API-KEY configued in config file")
    return emailobj,apikey


def parse_devices_file(apikey,verbose,package):
    fw_list = []
    try:
        object = open(DEVICES_FILE, "r")
    except Exception as e:
        logging.error("Error opening device file")
        logging.error(traceback.format_exc())
        raise FileError(e)
    for i, line in enumerate(object):
        if not line.startswith("#"):
            ip = line.split(',',1)[-2].rstrip()
            name = line.split(',',1)[-1].rstrip()
            fw = PanOsDevice(ip,apikey,name,API_TIMEOUT,verbose,package)
            fw_list.append(fw)
    if not fw_list:
        log_message = "No devices in devices file(devices.conf). Please add firewalls there, or don't use -f"
        logging.error(log_message)
        raise FileError("log_message")
    return fw_list


def start_logging(args="loglevel"):
	global loglevel  # Need to change global loglevel variable
	# Setting log level and logfile
	if args is None:
		loglevel = "DEBUG"  # Default is INFO
	else:
		loglevel = args
	# If invalid loglevel passed by user.. exit..
	if loglevel not in LOGLEVELS:
		log_message = "Unknown loglevel type: %s" % args
		print log_message
		sys.exit()
	# Set logging.basicConfig based on loglevel
	try:
		if loglevel == "DEBUG":
			logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(levelname)s -  %(message)s', datefmt='%Y/%m/%d %H:%M:%S')
		elif loglevel == "INFO":
			logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y/%m/%d %H:%M:%S')
	        elif loglevel == "WARNING":
        	        logging.basicConfig(filename=LOG_FILE, level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y/%m/%d %H:%M:%S')
	        elif loglevel == "ERROR":
        	        logging.basicConfig(filename=LOG_FILE, level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y/%m/%d %H:%M:%S')
	        elif loglevel == "CRITICAL":
        	        logging.basicConfig(filename=LOG_FILE, level=logging.CRITICAL, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y/%m/%d %H:%M:%S')
	except Exception as e:
		print "ERROR setting logging level"
		print(e)
		sys.exit(0)
	# Logging first message on script start
	logging.info("Script started, and logging to file initialized")


def main():
    # Get passed arguments
    args = get_passed_arguments()
    statuslist = [] # list used for storeing status messages
    # Setting verbose if set - false is default
    if args.v: verbose = True
    else: verbose = False
    # Start logging
    if args.loglevel:
        if args.loglevel in LOGLEVELS: start_logging(args.loglevel)
        else:
            log_message = "Unsupported log leve set %s. Exiting...." % (args.loglevel)
            logging.error(log_message)
            if verbose: print log_message
            sys.exit()
    else: start_logging("INFO")  # INFO is default
    # Set content type based on user input. Exit if -t is not set
    if not args.type:
        log_message = "-t content-type is mandatory. Please see -h for more info"
        logging.error(log_message)
        print log_message
        sys.exit()
    content_type = args.type
    if content_type not in PACKAGE:
        log_message = "Unsupported value set for content-type. Please check -h for help"
        print log_message
        logging.error(log_message)
        sys.exit()
    # Find newest file in directory based on content_type
    content_file = find_newest_file(content_type)
    # Parse config file
    emailobj,apikey = parse_config_file(args.e,verbose)
    # Parse device file - Find devices to install on
    device_list = parse_devices_file(apikey,verbose,content_type)
    # Run through all devices found and install
    for device in device_list:
        # Check and set installed versions on device
        try:
            device_status = device.check_installed_version()
        except UploadError as e:
            log_message = "Timeout when checking current content versions for device %s. Skipping device" % (device.name)
            statuslist.append(log_message)
            logging.error(log_message)
            logging.error(str(e))
            device_status = False
            pass
        if not device_status: continue # go to next device if we could not check current versions on device
        # Upload file - status (true or false) returned. True is succesfull upload, false is skipped or failed.
        try:
            upload_status = device.upload_to_device(content_file)
        except UploadError as e:
            log_message = "Error while uploading %s to %s. Skipping device" % (content_file, device.hostname)
            log.error(log_message)
            statuslist.append(log_message)
        # Only run install if upload status is true (succesfull)
        if upload_status:
            statuslist.append("SUCCESS: Upload of %s to %s - %s" % (content_file, device.hostname, device.name))
            # Argument w --wait determines if script should wait for completed install job
            if args.w: wait = True
            else: wait = False
            # Run install job
            try:
                install_status = device.install_on_device(content_file, wait)
            except InstallError as e:
                statuslist.append(str(e)) #If we get installerror - add it to statuslist
                install_status = False
            # Store status messages based on result of install job
            if install_status and wait: statuslist.append("SUCCESS: Installation of %s to %s - %s successfully completed" % (content_file, device.hostname, device.name))
            elif install_status and not wait: statuslist.append("""SUCCESS: Installation of %s to %s - %s started.
                                                        Did not wait for completion""" % (content_file, device.hostname, device.name))
            else: statuslist.append("UNKNOWN: Installation of %s to %s - %s returned unknown status. Check logfile for more details" % (content_file, device.hostname, device.name))
        else: statuslist.append("SKIPPED: Upload of %s to %s - %s. Content version we tried to install is the same or older as current version" % (content_file, device.hostname, device.name))
    # Print status messages to logfile, and/or prints them to stdout and sets email-content
    emailcontent = ""
    for status in statuslist:
        logging.info(status)
        if verbose: print status
        emailcontent = "%s\n%s" % (emailcontent,status)
    # if -e is set - send email with status messages
    if args.e:
        emailobj.content = emailcontent
        emailobj.send_email()
    # Print statusmessages to logfile


if __name__ == '__main__':
	main()
