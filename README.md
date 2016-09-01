#pan_dyn-update
Install dynamic updates on Palo Alto Networks firewalls and Panorama

Checks and finds for newest update file in subfolders panupv2-all-apps,
panupv2-all-contents,panup-all-antivirus, panup-all-wfmeta, panupv2-all-wildfire
and panup-all-wildfire. Installs latest update on devices defined in devices.conf if needed.

##Install
Install instructions are for linux only.
###Install the following repositories (using pip or method):
```
pip install poster
pip install bs4
pip install lxml
```
##Run setup.sh to make directories 
```
chmod +x ./setup.sh
./setup.sh
```
###Install pan-python from https://github.com/kevinsteves/pan-python

##Configuration
Two files needs to be modified to run the script.

In config.conf, the API-key must be configured, and optionally smtp settings for sending results with e-mail
```
apikey=XXXX
smtphost=smtp.gmail.com
smtpport=25
#smtpuser=<enter username if smtp authentication is used>
#smtppass=<enter password if smpt authentication is used>
smtpsender=sender@script.com
smtpreceiver=user1@script.com
```

In device.conf you need to configure the devices the script should install updates on. You can configure as many devices as needed.
Each line should contain ip/hostname and device name (separated with a comma). Device name is only used for reference in logs.
```
1.1.1.1,Firewall1
2.2.2.2,Firewall2
```
###Optional configuration
If needed some variables inside the script can be changed. Theese are located close to the top in pan-dyn-update.py.
```
CONFIG_FILE = "config.conf"  # Config file
DEVICES_FILE = "devices.conf"  # Devices file 
LOG_FILE = "log.txt"  # Log file used by script
API_TIMEOUT = 60  # API timeout - used when doing API calls and file uploads
```

##Usage
When running the script "-t contenttype" is mandatory. Supported values are:
* appthreat - Content updates with apps and threats
* app - Content updates with only apps
* antivirus - Antivirus update
* wildfire - Wildfire updates for PAN-OS 7.0.x and lower
* wildfire2 - Wildfire updates for PAN-IS 7.1.x and higher
* wf500 - WF-500 Content

Other optional arguments:
* -l LOGLEVEL - Set script log level. Can be DEBUG, INFO, WARNING, ERROR or CRITICAL
* -w - Script will wait for install jobs to complete on devices, and report back status
* -v - Verbose. Prints status messages to stdout
* -e - Sends e-mail with status messages for all uploads and installjobs when all processing is done.
