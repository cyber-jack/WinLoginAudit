# Send SUCCESSFUL or FAILED windows login notifications to Telegram Bot  

This is a windows schedule task to run a powershell script whenever a successful (Event ID 4624) or failed (Event ID 4625) event is detected in the windows event log.

The powershell script will execute and parse the event log to find the event that triggered the scheduled task.
The valuable information is then sent to a Telegram Chat Bot (Please add your own directly into the code)

You will be able to get instant Telegram messages whenever someone successfully or unsuccessfully tries to login to your Windows Computer. This allows you to improve your security posture and become aware of malicious attempts to access your resources, whether manually attempted, or done by a bot with a passwordlist to attempt brute force logins to your Windows Machine.

To install, import the XML scheduled task and allow it to run as an administrative user. Point the powershell argument to the location of where you saved the .ps1 script file.

Pull requests or improvement suggestions welcome as this is Beta code.
