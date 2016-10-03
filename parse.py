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

"""Contains classes for parsing XML and sending Email

Used in both content_installer.py and pancom.py

"""
from bs4 import BeautifulSoup
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

import time
import smtplib
import logging
import traceback


# SMTP-config variables - set in config.conf
smtpmessage_template = "This is an automatically generated e-mail. Script pan-dyn-update.py has performed the following task:\n"

class SoupException(StandardError):
    pass

class XmlReader:
	def __init__(self, content):
		self.content = content
		self.soup = BeautifulSoup(content, "lxml-xml")

	# Static methods


	def find_serial(self,searchstring):
		output_list = []
		for tags in self.soup.find_all(searchstring):
			serial = str(tags['name'])
			output_list.append(serial)
		return output_list


	def find_jobid(self):
		try:
			str = self.soup.find('job').text
			return str
		except:
			raise CheckError('Couldn\'t find any matching item %s' % s)


	def findnextjobid(self):
		try:
			str = self.soup.find('nextjob').text
			return str
		except:
			raise SoupException("Couldn't find any matching item in method findnextjobid()")


	def find_status(self):
		try:
			for tags in self.soup.find_all('job'):
				child_status = tags('status')
				for statustag in child_status:
					status = statustag.text
				child_progress = tags('progress')
				for progresstag in child_progress:
					progress = progresstag.text
			return status,progress
		except:
			print 'Couldn\'t find any matching item'


	def find_content_versions(self):
		try:
			for tags in self.soup.find_all('system'):
				child_threat = tags('threat-version')
				for version in child_threat:
					threat_version = version.text
				child_app = tags('app-version')
				for version in child_app:
					app_version = version.text
				child_av = tags('av-version')
				for version in child_av:
					av_version = version.text
				child_wf = tags('wildfire-version')
				for version in child_wf:
					wf_version = version.text
			return app_version,threat_version,av_version,wf_version
		except:
			print 'Couldn\'t find any matching item'


class EmailSender(object):
    def __init__(self,smtpsender,smtpreceivers,smtphost,smtpport):
        self.smtpsender = smtpsender
        self.smtpreceivers = smtpreceivers
        self.content = None
        self.smtphost = smtphost
        self.smtpport = smtpport
        self.smtpuser = None
        self.smtppass = None


    def send_email(self):
		message = "%s \n\n%s" % (smtpmessage_template,self.content)
		try:
			msg = MIMEMultipart()
			msg['From'] = self.smtpsender
			for receiver in self.smtpreceivers: msg['To'] = receiver
			msg['Subject'] = "Pan Firewall Update - report"
			msg.attach(MIMEText(message, 'plain'))
			session = smtplib.SMTP()
			session.connect(self.smtphost,self.smtpport)
			session.starttls()
			if self.smtpuser is not None: session.login(self.smtpuser,self.smtppass)
			text = msg.as_string()
			session.sendmail(self.smtpsender,self.smtpreceivers,text)
			session.quit()
			logging.info("Email was successfully sent to configured receivers i config.conf")
		except smtplib.SMTPException:
			logging.error("ERROR: Unable to send email - please check config in config.conf")
			logging.error(traceback.format_exc())
		except socket.gaierror:
			logging.error("ERROR: unable to send email - please check config in config.confg")
			logging.error(traceback.format_exc())
