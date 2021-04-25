# Receive instant SUCCESSFUL or FAILED windows login attempt notifications on your Discord chat app (Android/IOS/Windows/MAC) 

This is a windows scheduled task to run a powershell script whenever a successful (Event ID 4624) or failed (Event ID 4625) login event is detected in the windows event log.

The powershell script will execute and parse the event log to find the event that triggered the scheduled task.
The valuable information is then sent to a Discord Channel. (Please add your own directly into the code)

You will be able to get instant Discord messages whenever someone successfully or unsuccessfully tries to login to your Windows Computer. This allows you to improve your security posture and become aware of malicious attempts to access your resources, whether manually attempted, or done by a bot with a passwordlist to attempt brute force logins to your Windows Machine.

To install, import the XML scheduled task and allow it to run as an administrative user. Point the powershell argument to the location of where you saved the edited .ps1 script file.

Edit the .ps1 script directly, and add your Discord webhook.

Pull requests or improvement suggestions welcome as this is Beta code.

# Create a webhook

Detailed instructions for setting up the Discord Webhook: https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks

Simplified instructions:

1. Open your Server Settings and head into the Integrations tab:
2. Click the "Create Webhook" button to create a new webhook!

![2018-01-06_15-53-12](https://support.discord.com/hc/article_attachments/1500000463501/Screen_Shot_2020-12-15_at_4.41.53_PM.png)

# Create your executable
1. Edit LoginAudit.ps1 and add your Discord Webhook
2. Use PS2EXE-GUI to convert your script into a binary (make sure you uncheck "Compile a graphic windows program")
3. (OR) Enable Powershell Scripts (see next step)
4. Place the executable/script in your home folder

# (optional) Enable Powershell Scripts
1. Open PowerShell as an Administrator on the windows machine
2. Type:
```
set-executionpolicy remotesigned
```
3. Type A and press Enter

![2018-01-06_16-30-40](https://user-images.githubusercontent.com/18201320/34640635-0fd9e8de-f2ff-11e7-9081-e6ac47c640d2.png)

# Edit Security Policy
Run secpol.msc on the machine and navigate to Security Settings > Local Policies > Audit Policy and change the "Audit account logon events" and "Audit logon events" policies to audit SUCCESS and FAILURE events

![2018-01-06_15-17-58](https://user-images.githubusercontent.com/18201320/34640213-21fb131a-f2f7-11e7-81a3-8254ade34998.png)


# Import the Scheduled task XML
1. Open Windows Task Scheduler
2. Select "Import Task"

![2018-01-06_16-34-00](https://user-images.githubusercontent.com/18201320/34640660-78298f52-f2ff-11e7-80c8-4f2877699e52.png)

3. Import the LoginAudit.XML file - Make sure to change the binary/script location at the bottom
4. Change the task name if necessary
5. On the "Actions" tab, ensure the parameter of the Powershell action points to the actual location of the edited LoginAudit.ps1 file (your TOKEN and GROUPID should already be saved into this file.)
6. On the "General" tab, click on "Change User or Group" and select a local administrative user.
7. Click OK and type the correct password for aforementioned user.

NOTE: The scheduled task is created to filter out 4624 and 4625 events as follows, since a successful execution of the scheduled task itself, will generate an event in the log, thus without the filter, the task will enter into and endless loop.
```
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
	*[System[EventID=4624]
	and
	EventData[Data[@Name='LogonType'] != '4']
	and 
	EventData[Data[@Name='LogonType'] != '5']
	and
	EventData[Data[@Name='SubjectUserSid']!='S-1-0-0']
	and
	EventData[Data[@Name='TargetDomainName']!='Window Manager']
	and
	EventData[Data[@Name='TargetDomainName']!='Font Driver Host']
	and
	( System[TimeCreated[timediff(@SystemTime) &lt;= 60000]])
	]
	
	or
	
	*[System[EventID=4625] 
	and
	EventData[Data[@Name='LogonType'] != '4']
	and 
	EventData[Data[@Name='LogonType'] != '5']
	and
	( System[TimeCreated[timediff(@SystemTime) &lt;= 60000]])
	]
  </Select>
  </Query>
</QueryList>
```

# Test it out
1. Open a command prompt window and type:
```
runas /user:test cmd
```
2. Press Enter, Type any password and press Enter again
3. You should now get an instant Discord message indicating the failed login attempt

