
This course will include the subjects below:

- Inventory
- Backups
- Phishing Prevention
- Internet Browsing Protection
- Patching
- Access Control
- Risk Analysis
- Network
- Incident Response for IT Security

  

This course was written by Julien Garcia. You can find his social media accounts below.


### Inventory

Protecting your infrastructure requires knowing what devices are connected to your network, what applications are being used, who has access to them, and what security measures are in place.

  

## **What should your inventory contain and why?**

As with all IT security issues, you will need a complete inventory. This inventory should include at least the following information:

- the hardware of each workstation and server 
- the software installed with the exact version 
- the date of the last report

  

## **End-of-Life Equipment**

Thanks to your inventory, you have been able to isolate all the equipment (hardware and software) at the end of their support. Equipment that is no longer maintained is equipment that will no longer receive security patches. It is then necessary to exclude from your network all the equipment that cannot be maintained. In case of extreme necessity, a risk acceptance by a CISO(Chief Information Security Officer) must be performed and traced in your inventory. This analysis must be reviewed at regular intervals, ideally at each new vulnerability discovered.

  

## **Secure Boot**

The secure boot must be enabled on all your compatible devices. This feature ensures that the computer boots using only manufacturer-approved software. This is a feature that has been available for 10 years, so it is unlikely that a problem will occur if you have standard usage.

  

## **Softwares List**

In order to reduce the attack surface, it is important that your company has a strict policy regarding authorized and unauthorized software.

  

### **Allowed Softwares**

To do so, the use of GPO (Group Policy Object) or [Intune](https://learn.microsoft.com/en-us/mem/intune/fundamentals/what-is-intune) allows you to provide your users with a quickly available software library without the need for administrative rights to its stations. This avoids that your users have to download the installation programs themselves and therefore limits the risk of downloading a malicious program.

  

### **Forbidden Softwares**

In the same way, whether via Intune or AppLocker, it is necessary to block software identified as forbidden (either because you do not legitimize the application or because its version is subject to a CVE (Common Vulnerabilities and Exposures) that is dangerous for you). Each use of a prohibited application must be reported to your company's IT team.

  

## **Security Hardening**

Does your company rely on proven hardening guides to define the configuration of your devices? These hardening guidelines can cover different levels such as:

- Station handover procedures with prerequisite checklist
- Audit of the secure configuration of the devices 
- Alert in case of configuration modification

This hardening can be done in several ways, such as Ansible, GPO, or Intune.

  

## **Antivirus / EDR**

Make sure that your company deploys an antivirus, or even an EDR on the entire fleet, starting with the devices that are critical to your business. Do not forget to set up a follow-up of the generated alerts.


### Backups

Backups are not a mechanism for fighting Ransomware but they are your last line of defense. A non-operational backup system following an attack could jeopardize the survival of your business.

  

### Rule 3-2-1

As a basic rule and the minimum expected for an infrastructure, the 3-2-1 rule states that you must:

- Have at least three copies of your data 

- Store on two different media

- One of which must be an offsite external backup

  

### Three Copies

The principle is to have your data on the server and two backups. This is to avoid that a failure makes your backups inoperative.

  

### Two Different Media

Here, two media should not be understood as necessarily two different physical formats (hard disk and LTO tape) but as having one's backup on two different and unrelated points. Thus, it is possible to have two copies of the backup on hard disks if the two are not stored in the same datacenter, not linked via the same software RAID (Redundant Array of Inexpensive Disks), etc.

  

### One Offsite External Backup

The idea behind this request is to have a backup stored outside your building that contains the main data to protect against risks such as fire.

  

## Rule 3-2-1-1-0

This rule is to be applied at least on the critical resources of your company. Identical to the 3-2-1 rule, it adds two conditions: 

- 1 offline copy

- 0 errors during the restoration

  

### One Offline Copy

This is about having a backup that is not connected to your network and any IT infrastructure. The goal is to avoid that if an attacker has compromised your network, he can intervene on this backup.

  

### Zero Errors During The Restoration

This point seems logical, but it is advisable to regularly test the backups made and check that they can be restored without errors. It would be a shame if once restored, it is discovered that a file on the database server is actually damaged.

  

## Minimum Storage Time

It is important that the backups allow to restore at least 30 days old data. Why 30 days? Because the average time between the intrusion in the park and the detection by the company is about this time.

  

## Backup Tests

Now that your data is backed up according to best practices, it is important to ensure that your test restores are tracked and that each server is restored at least once a year.



### Phishing Prevention

Phishing attacks represent one of the biggest initial attack vectors along with the exploitation of vulnerabilities on your online servers.

  

### **Antispam and Email Protection**

Do all emails received by your employees pass through a spam filter? Does your Antivirus (AV) software analyze the attachment in the mail? Is this configuration reviewed and kept up to date with new threats?

  

### **Analysis Procedure**

When one of your employees receives an email and has a doubt, she/he should have the possibility to contact someone to perform an analysis of the email.

  

### **Phishing Drill**

It is often experienced as an attack on the staff, it may be worthwhile to conduct a test to ensure that your staff is properly aware.



### Internet Browsing Protection

Filter connections to unauthorized websites, suspicious domain names and known malicious domain names.

  

### **DNS Filtering**

Block dangerous sites and filter unwanted content through your firewalls. In addition to "unprofessional" categories like +18 adult content, there is one category that is rarely blocked, URL shorteners. This service is massively used, especially for phishing. Once the blocking is configured, it is necessary to control the blocked sites that your employees have tried to visit.

  

### **Centralized Management of Browsers**

Updating browser security settings can make it harder for malware to install. For example, to reduce the ability to install plug-ins or to disable the automatic execution of certain types of content.



### Patching

Deploy patches to your software and firmware as quickly as possible. Enable automatic updates whenever possible.

  

### **SLA for Patching According to CVE**

**What is SLA?**

A service-level agreement (SLA) is a contract between a service provider and its customers that documents what services the provider will furnish and defines the service standards the provider is obligated to meet.

_source: techtarget.com_

  
  

Have you set up a maximum update time for your workstations/servers/softwares? If yes, do you take into account criteria such as the CVSS (Common Vulnerability Scoring System) score, the fact that the server to be patched is on the Internet-facing or not, that the flaw is known to be exploited (0-day)?

### Access Control

Implement policies, processes and technologies that ensure that only authorized users are granted the least privileges necessary. There is no magic bullet here that works for everyone, you need to adapt, take it step by step.

  

### **Password & MFA**

The lowest level of protection is the implementation of a password policy within your environment. In the case of a Windows environment, this policy should be set in the "Default Domain Policy" to ensure that it applies to all computers. 

Whenever possible, use stronger mechanisms than password authentication, such as biometrics, one-time passwords and application tokens. Multi-factor authentication (MFA), via SMS or application authenticator, is highly recommended, starting with privileged users and extending to all users.

  

### **Zero Trust**

Identify and disable unused accounts, eliminate shared accounts, remove unnecessary privileges and enforce strong password policies.

  

### **Audit of Account Usage**

Monitor and analyze user activity for anomalous behavior such as access attempts outside of normal business hours or from unusual locations. Your fleet should not contain more than 15% of accounts with the "domain administrator" privilege.


### Risk Analysis

Use risk assessments to prioritize the allocation of resources and investments.

  

### **Return to Service**

Has your company conducted a study to define which resources should be recovered first? This analysis can also be used to estimate the impact of disruptions and identify allowable downtime.

  

### **Review of Risks on Connected Networks**

Every connection to your company is a risk to it. Whether it's within an entity of your company or a partner. Keep in mind that each of these parties may not have the same security requirements as you do. 

Are your partners committed to the same level of security as you, do you know how quickly they update when a vulnerability is disclosed? Are they committed to not using default certificates on VPNs? If they use online solutions, are you sure that their configuration is in line with your security needs?


### Network

Monitor your organization's incoming and outgoing Internet traffic.

  

### **PCAP**

Use the SPAN ports of your network equipment to capture your network activities. This capture will allow you to detect abnormal behavior (increased use of a protocol, abnormal destination addresses, etc.) as well as to perform a post-mortem in case of compromise.

  

### **Segmentation**

Segmentation divides a computer network into smaller parts. Network segmentation improves network performance and security by reducing the attack surface and limiting the range of an attack. The use of VLAN, PVLAN allows you to separate your different networks. 

Are the administration interfaces of your network equipment available from Alice's (or whoever) accounting station? Is the remote office service only available on a dedicated network?

  

### **Review of Blocked Flows**

Now that your corporate network is segmented, and flows are prohibited, the next step is to set up a review to identify the origin of the requests that get blocked with your new policy. It could be a compromised workstation, an application that went under your radar in the inventory, etc.

  

### **Alert Outside of Standard Use**

Once all this is in place, you can generate alerts in case of abnormal network usage. Besides the security gain, these alerts could allow you to identify weak points in your organization, for example when your backup tools saturate the network.


### Incident Response for IT Security

Make sure you have clear processes in place and known to your staff regarding escalation of major incidents. A major incident that is quickly escalated to the experts can allow you to mitigate the impact of a cyber attack.


You can find a tutorial on how to create an incident response plan at the button below:

[Windows Incident Response Course](https://app.letsdefend.io/training/lesson_detail/how-create-incident-response-plan-windows)


### How to Create Incident Response Plan?

## What is incident response?

Incident response is an approach to managing a security incident process. An incident response plan is needed to approach security incidents systematically. A successful incident response plan includes the following 6 stages:  
  
1- Preparation  
2- Identification  
3- Scope  
4- Eradication  
5- Recovery  
6- Lessons Learned  
  

## 1- Preparation

**Creating a Central Registration System**  
  
It is important in terms of saving time that all data can be examined from a single point with a central log collection system that can manage large files.  
  
**Time Synchronization**  
  
Enabling NTP on all devices in the network is important for matching the time information of the logs collected.  
  
**User Account Management**  
  
The fact that the user names of different accounts belonging to personnel are the same and different from other personnel makes it easy to monitor user activities in the event of an incident.  
  
**Management of System and Service Accounts**  
  
The administrators of the services and systems used should be appointed and a document should be created on how to reach these managers if needed.  
  
**Asset Management**  
  
Instant access to information such as devices, operating systems, patch versions, and critical status should be available.  
  
**Secure Communication**  
  
If necessary, the team may need to communicate independently of the internal network, for such cases mobile phone or secondary emails can be used.  
  
**Legal Transactions**  
  
The method of who will initiate the judicial process and in which situations should be determined before the incident occurs.  

## 2- Identification

**Review**  
  
For a potential suspicious incident, preliminary information about the incident should be gathered. Then it must be decided whether the situation is a suspicious event or not.  
  
**Assignment**  
  
The first person to examine the incident must be determined. The person should take notes about the review.  
  
**Using the Checklist**  
  
There should be checklists for the analysis to be made in order to ensure consistent responses to incidents.  

## 3- Scope

**Characterize the event**  
  
Since determining the event will determine the actions to be taken, it is important to determine the type of the incoming event. EX: DDoS, malware infection, data leak …  
  
**Taking Action**  
  
Action should be taken according to the technique used to intercept the attacker's method quickly. If there is an account that it has captured, simple measures such as account deactivation and IP blocking should be done quickly.  
  
**Data collecting**  
  
The image of the volatile memory along with the firewall, network traffic and other logs will be required for the investigation.  
  
**Isolation**  
  
Unplugging the compromised system could be a solution, isolating it is a more viable solution.  
  
After the systems affected by the incident are determined, the possibility of the attacker's spread in the network is cut and volatile information is collected, the next step can begin.  

## 4- Eradication

**Identifying the Root Cause**  
  
With the information obtained in the 2nd and 3rd stages, the root cause of the event should be determined. The attacker must then be completely eliminated.  
  
**Determining Rootkit Potential**  
  
If rootkits are suspected in the system, the disk should be cleaned and a clean backup installed. After the installation, the latest updates of the existing applications and systems should be installed.  
  
**Improve Defense**  
  
Operating systems, applications used, network, DMZ etc. The deficiencies of defense in areas should be determined and work should be done on how to make improvement.  
  
**Vulnerability Scan**  
  
Potential attack points on networks and systems should be identified and corrected by performing vulnerability scans.  
  
When the necessary arrangements are prepared to prevent the event from recurring, the recovery phase can be started.  

## 5- Recovery

**Verification**  
  
Verify that logging, systems, applications, databases, and other operations work correctly.  
  
**Restore** At this stage, the restore operation is coordinated.  
  
**Monitoring**  
  
Systems should be monitored for recurring events.  
  
When there is no repetitive harmful situation or unusual activity, the next step is taken.  

## 6- Lessons Learned

**Writing a Follow-up Report**  
  
The report includes the examinations with the expert and the executive, the stages of good and bad working in the intervention plan, and the recommendations regarding the process. The report should be written in a way that the manager is sure that the event has been closed.



### Incident Response Procedure

### How Does the Procedure Proceed?

In a SOC (Security Operation Center) environment, the action taken against an incident is important. Everyone should not use their own method they came up with, but methods that have had their frameworks previously determined should be used so there is consistency and everything proceeds accurately during a time of crisis. In this section, we will talk about how we can keep the base of consistency in response to incidents. This section is important to understand the big picture.

![[pro.png]]

### Alert

After the logs collected through the EDR, IDS, IPS, WAF, and similar security tools that are found in the SOC, rule correlation sets are formed through the SIEM to determine suspicious activity. Thus, in the case of an unwanted situation, a new alert is created.  

### Analyze

In an ideal SOC environment, there are Tier 1 analysts present to conduct the preliminary analysis on alerts that come through the security tools. This analyst analyzes the incoming alert and determines whether it is a false positive or not. For example, an alert can be formed after sending a request to a malicious URL address; however, the URL address is not actually malicious. The Tier 1 analyst controls this procedure and eliminates incoming alerts.  

### Investigate

After it is determined that the incoming alert is not a false positive, the investigation procedure begins, and the source of the attack is investigated. In addition, the amount of progress the attacker has made since the beginning of the attack is investigated.  

### Assess Impact

The systems that have been affected by the attack are determined and the amount of damage present in the current situation is assessed and evaluated. For example, in a system that has been affected by ransomware may not have had all its data encrypted. Determinations similar to this have to be conducted to have an assessment of the current situation.  

### Contain

After determining the systems affected from the attack, it is crucial that the situation is handled with control and prevented from spreading. Thus, the affected devices must immediately be isolated from the network. Let’s continue with the ransomware example. A dangerous ransomware will want to spread itself to other devices. In order to prevent the interaction with the other devices, the device must be isolated from the network.  

### Respond

After all the mentioned steps above are completed, the response process is initiated. At this step, the root cause of the situation is determined, the present dangers are removed, the systems are brought back to a working state, and lessons are made from the situation that has occurred. The main topic of this training will be the details listed under this title. In future topics, we have showed you how to do this with details.


### 3 Important Things

When analyzing a system that has been hacked or believed to have been hacked, regardless of the processing system, there are 3 questions that must be answered. The responses to these questions may change or end the continuation of the analysis.

- Is there a malware that is actively in the system?
- Is there any suspicious internal or external communication?
- Is there any persistence?
  

### Is there a malware that is actively in the system?

If there is anything malicious that is actively running in the system, you may conduct a backward analysis to investigate how it came there in the first place. The easiest way to do this is conducting a process analysis. We will teach you the details of process analysis in the future. However, to give a short example: a “powershell.exe” childprocess under an “excel.exe” process is suspicious and must be investigated.  

### Is there any suspicious internal or external communication?

An attacker must form an interaction with the server in order complete procedures like controlling the system or extracting data from it. This interaction will form network traffic. An anomaly determination can be conducted by analyzing the connections made in that system currently and in the past. For example, in the case of a connection being established with an IP with a bad reputation, or data traffic at rates of large GBs between a certain IP, or connections made between anormal ports can be cases that should be carefully investigated.  

### Is there any persistence?

When the actions of the attacker until this day are observed, it can clearly be seen that the attacker aims to be permanently present in the system that has been taken over. The reason behind this can be the fact that the attacker may not have been able to complete a certain transaction quickly and may need to return to complete it later and the thought that he/she should leave an open door because he/she might need it in the future again.  
  
During your analysis, you may not be able to determine an active malicious presence or suspicious traffic. Maybe the attacker has kept a backdoor that can trigger itself once a week. Thus, you must know the procedures used for permanence and you must examine these within the system.  
  
Answering the 3 mentioned questions is important. The responses to these questions may change the continuation of the analysis. To answer these questions, there are certain places you must technically analyze. We will start talking about these in the upcoming chapter.


### Free Tools That Can Be Used

There are numerous free tools that can be used during the incident response process. Even though some procedures can be done manually, it is important that you use these tools to speed up the process, because with certain cases, we may be racing against time. During the scope of this education, we will use some free to use tools. Some of these are:  

#### Process Hacker

Is a tool that can be used to analyze the active working processes in the system in detail. Download: https://processhacker.sourceforge.io/downloads.php  

#### FullEventLogView

Collects the Windows event logs in a single window. May collect proof about correct filters that are to be applied especially when the attack time frame is known. Download: https://www.nirsoft.net/utils/full_event_log_view.html  

#### Autoruns

Is Microsoft sysinternal tool. Helps determine the attacker’s persistence actions. Download: https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns  

#### LastActivityView

Sorts activities that have occurred on devices with the data it has collected from various sources. May be very beneficial when a specific time filter is applied. Download: https://www.nirsoft.net/utils/computer_activity_view.html  

#### BrowsingHistoryView

Reads the history of the web search engine on the device and shows it on a single screen. May be used to determine attacks like phishing and web exploit. Download: https://www.nirsoft.net/utils/browsing_history_view.html  
Note: As we have mentioned before, there are different equivalent tools that can be used. It’s not the tool we use that’s important, but it’s what we analyze/control with those tools. You can even code your own tool.


### Live Memory Analysis - 1

The best way to identify a malicious activity that is actively running in the system is to conduct a memory analysis. If the attacker(s) is accessing the system remotely at that moment, and if he/she is stealing data or making an interaction in any way, there is a process that is allowing this. To identify the process allowing this, a memory analysis can be conducted.  
  
While explaining this topic, we will benefit from the “Process Hacker” tool. As we have explained before, there are different equivalent tools like this. The important thing is to know what to control, not what tool we use.  
  
NOTE: You should run as Administrator to access all data!


![[mem1.png]]


The Process Hacker tool presents very detailed data regarding the processes in the system. Above, you can see the process relations, PID numbers, and the user information running in its most basic form.  
  
Let’s return to the analysis. There are 3 critical points we must pay attention to while conducting a memory analysis:  
  
- Process Tree
- Network Connections
- Signature Status
  

### Process Tree

It is important to know what the normal statuses are while conducting a memory analysis. For example, it is normal to have a “chrome.exe” named childprocess under the “chrome.exe” process because it may create different subprocesses for different tabs.


![[mem2.png]]


  
What if we saw a “powershell.exe” process that has been created under the “chrome.exe” process? We cannot react normally to a PowerShell creation under a chrome process. We must suspect an exploitation situation and examine what the PowerShell has done and what commands it invited.  
  
**Example 1 – WebShell Detection**  
  
Let’s take a look at the process tree below. A “powershell.exe: childprocess has been created under a process owned by the web server. It could have been “cmd.exe” instead of a PowerShell. Following, a “whoami” and “net user” command was run. We cannot expect a PowerShell to run under a web server process other than extraordinary circumstances. In addition, we definitely cannot expect any enumeration commands to run on top of this.

![[mem3.png]]


We can come to this result in this situation: If a cmd or a PowerShell process has been created under a web server process, we must suspect a webshell and investigate it.  
  
**Example 2 – Malicious Macro Detection**  
  
Let’s think of the “Winword.exe” process. We know it is created when a word document is opened. Is it normal for a powershell.exe to form under a Winword.exe process? What if, in fact, this PowerShell is being run with a command encoded with base64. This situation is not normal and is most probably created due to a file with a malicious macro embedded in it being opened.

![[mem4.png]]

#### Checking With Process Hacker

We theoretically mentioned how we can identify suspicious activity that derive from a process tree with various examples. How can we check for these on a real machine?


![[mem5.png]]


When we look at the situation above, we can see that python.exe has been formed under cmd.exe. This situation may be legal but may also have run a malicious python command. In order to understand this, we must double-click on “python.exe” and check which file/command was run within which parameters.


![[mem6.png]]


When we look at the “command line” area, we see that the manage.py file was run within the parameters of “runserver” and in “current directory” we can see where the procedure was conducted. We cannot definitely say that there is a suspicious situation here. In order to understand whether the situation is suspicious or malicious, we must analyze the “manage.py” file. As seen, this file is located at “C:\Users\gunal\Documents\Github\LetsDefend\letsdefend\”  
  
The network connections and signature status points that must be checked during a memory analysis will be explained in the next part.

### Live Memory Analysis - 2

In the second section of memory analysis, we will examine the “Network connections” and “Signature status” situations.  

#### Network Connections

Attacker(s) need to leave a backdoor in order to access the device remotely and steal data. In order to identify this backdoor, we must check the active network connections during our analysis. The topics we need to be careful about here are process name, remote IP address and port number.  
  
Initially, we can see the processes creating the active network connection by opening the “Network” tab in Process Hacker.

![[mem21.png]]

  
In the “remote address” section, we can see what process has communicated with which address and we can see which port it has connected to through “Remote Port”. The first thing we need to check here is whether we have a process which we expect to make a connection. When we look at the image above, we see that Chrome, Discord and Evernote applications establish a network connection. When we look at the port information, we can understand that the connection was made through port 443. In the initial analysis we conducted, we were not able to identify any unnatural processes or a port that is not commonly used. If our suspicions are ongoing, we can conduct a search regarding the IP address at reputable sources like VirusTotal, AbuseIPDB.  

#### Signature Status

Another way to identify suspicious events is to check whether the file running the service is signed or not. The fact that a file is signed does not always mean it is legal. The most prominent example to this is the recent incident of SolarWinds. In the SolarWinds incident, the attackers changed the source code before the software was published and the relevant units had signed the malicious code. Thus, a software that looked like it was owned by SolarWinds but was actually a malware was distributed in the public.  
  
Open the “Process” section in Process Hacker and right click on the “Name” section that is right below it and click “Choose columns”. In the window that pops up, send the “verification status” and “Verified Signer” choices to the “Active Columns” section and click OK. Thus, you will be able to view the signature status of the files relating the actively running processes and by whom it was signed.

![[mem22.png]]

![[mem23.png]]

### What Did We Learn?

- During the memory analysis, we must carefully pay attention to the “Process Tree”, “Network Connections”, and “Signature Status” situations.
- How we must use the Process Hacker tool for Live Memory Analysis
- How to distinguish normal and suspicious situations.

### Users

A method that is commonly used by attackers to maintain persistence is to create users. In fact, maintaining persistence is not the only reason why this is conducted. We observe that when attacker(s) take control of the “Administrator” account, they create new users. Because this is an important user, and its activity may be regularly tracked. Thus, they create a new user that will not attract a lot of attention and, if possible, they increase that user’s privileges.  
  
The users that are created usually include keywords like “support”, “sysadmin”, “admin”. In most companies, users with names like these will not attract much attention.  
  
During an incident response procedure, there are 2 things that we must quickly evaluate.  
  
- Is there currently a user in the system that should not be there?
- Has a user been created during the attack and deleted after that?
  
  

#### Suspicious User Detection

To list the currently active users in the system, we can use the “net user” command via cmd.



![[user1.png]]

As a result, if there is a user that should not be there and we need more detailed information regarding this specific user, we can conduct a search my typing “net user USERNAME”.


![[user2.png]]

In this example, if the “Last logon” and “Password last set” values are paired with the time of the attack, we can approach the situation with suspicion.  
  
Another method is to maintain control through “lusrmgr”. For this, activate “run: with “Windows + R” and click OK by typing “lusrmgr.msc”


![[user3.png]]

In the window that pops up, you can choose the “Users” group and list the users.

![[user4.png]]

If you are suspicious of a user after this controller, you can focus on the activity of that user in your following analysis period.  
  

#### Users That Have Been Created in The Past

Attackers, after they create a user and conduct the relevant procedures, may delete users when they are done to minimize the trail left behind. In this case, we will not be able to view these users in the commands we conduct with “net user” or “lusrmgr”. What we must do is check within the “Security” logs to observe whether a user has been created in the past or not. To do this, we can use the log “Event ID 4720 – A user account was created”.  
  
After opening the “Security” logs with “Event Viewer”, we can filter the logs with Event ID “4720”.


![[user5.png]]

![[user6.png]]

In the window that pops up, we input “4720” as the Event ID.

![[user7.png]]

![[user8.png]]

  
When we look at the result that appears, we can see that the user “LetsDefend” has created a user named “SupportUser” on “10/10/2021 10:07”. The takeaway we must get from this is that; the user “LetsDefend” has been taken over or an access that can allow commands to be run has been made. From this point on, both the “LetsDefend” and “SupportUser” users’ activities must be tracked.  
  

### ADDITIONAL

In order to capture suspicious situations about users, you can inquire the users added to the “Administrators” group during the timeframe of the attack. Thus, you will have immediately caught a user that should not have been added. For this, you can use the event ID below.  
  
- Event ID 4732 – A member was added to a security-enabled local group.
  

### What Did We Learn?

- Attackers may use generic names like “support” or “admin” after taking control of the system.
- The activities of the user that has created a new user must also be tracked in addition to the activities of the new user.
	- While tracking previous activities, the 4720 and 4732 EventID logs will be beneficial.

### Task Scheduler

One of the most used persistence methods is to create scheduled tasks. Most malicious things from viruses to ransomware use scheduled tasks to maintain persistence. The attacker, by using scheduled tasks, ensures that the malicious file runs at regular intervals. Thus, the attacker ensures that the commands he/she wants to run are run actively and regularly. There are various ways to identify the actively present suspicious scheduled tasks that are running in the system. First, let’s show you how this is done by using “Autoruns”, which is a sysinternals tool.

#### Autoruns

With the autoruns tool, we can identify commonly used permanence methods that attackers used like Registry, Startup, and Schedule Task. We run it as an intermediary admin and go to the “Scheduled Task” tab.

![[task_schedule1.png]]

  
We do not have many scheduled tasks in front of us. When necessary, we can examine each one individually and identify the suspicious one. However, let’s think of what we can do if we have a high number of scheduled tasks, and we are racing against time. In order to conduct an initial elimination, we can start with scheduled tasks that do not have a “Publisher”. The fact that there is a publisher does not make it completely trustworthy, however, it is a higher probability that suspicious tasks do not have publishers.


![[task_schedule2.png]]


Now the number is down to 3. What we must do now is analyze the file located in the “image Path” that will run when the time comes.  
  
When the “important.bat” file is examined for the “Update-Daily” task, we can see that the commands below are run.

![[task_schedule3.png]]

Thus, we see that the actual goal of the attacker is to create a user named “User123” and add it to a relevant group for it to be able to run an RDP. The attacker chose not to do this manually by hand, but with a scheduled task.  

#### Task Scheduler

In order to identify suspicious tasks, those that do not want to download the autoruns tool may use the default “Task Scheduler” that is present in the operating system.

![[task_schedule4.png]]

Even though there aren’t any additional pieces of information presented here similar to autoruns, when you click on the relevant task, you can see and analyze which file or command was run.

![[task_schedule5.png]]

#### CMD

Even though it is not commonly preferred, if you do not have the chance to use an interface, you can view the scheduled tasks with the ‘schtasks’ command in the command line interface.

![[task_schedule6.png]]

#### Deleted Tasks

What if after all inquiries we do not observe a suspicious task? Can the attacker have created a task that deletes itself after it runs?  
  
In order to determine a situation like this, we must examine previous logs. Event logs will run to the rescue during situations like these. If you want to access relevant logs through Task Scheduler, you may do so through the “Applications and Services Logs-Microsoft-Windows-TaskScheduler Operational.evtx” section located in Task Scheduler.

![[task_schedule7.png]]

Or you may track the “Security” logs below:  
  
Event ID 4698: A scheduled task was created  
Event ID 4702: A scheduled task was updated  
  
For example, in the log below, we can see that a scheduled task was created on the date 10/23/2021

![[task_schedule8.png]]

When we observe the “action” section, we can see the file/command that the task attempted to run. Even if this task is not currently active in the “Task Scheduler”, we have identified with a log analysis that this task was created in the past.  

#### What Did We Learn?

We talked about how we can identify suspicious activity in scheduled tasks which is a method that attackers commonly use. We also learned how we can detect tasks that are not currently active and have deleted themselves. Now you know what to do in situations like this and where to look. You can complete the practices below and solidify your theoretical information.


### Services

Attackers may create a new service or change a current service in order to run malicious commands. They may use legal code names like “Chrome Update” in order to make it difficult to identify the service they have created or changed. In order to detect a newly created service from Event Logs, the log with ID “4697: A service was installed in the system” can be used.  
  
In addition to persistence, they constantly stop services like “Windows Defender”, “Firewall”, etc. that are run for safety precautions in order to easily conduct hacking activities.  
  
For these reasons, when analyzing a Windows device, me must examine which services have been created/changed and which systems have been stopped.


### Registry Run Keys / Startup Folder

Another important method that is used is to play with the “Registry” values or leaving a file in the “Startup” file. Thus, it is ensured that the requested file is run when a user opens a session.  
  
According to a study by MITRE, 100+ malicious software’s that APT groups utilize use this technique.  

### Startup

In order to view the files added to the startup file, the indexes below must be checked.  
  
- C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
  
- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

![[reg1.png]]


### Registry Run Keys

  
**The following run keys are created by default on Windows systems:**  
  
● HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run  
● HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce  
● HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run  
● HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce  
  
  
**The following Registry keys can be used to set startup folder items for persistence:**  
  
  
● HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders  
● HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders  
● HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders  
● HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders  
  
  
  
**The following Registry keys can control automatic startup of services during boot:**  
  
  
● HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices Once  
● HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices Once  
● HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices  
● HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices  
  
  
  
  
**Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:**  
  
● HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run  
● HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run  
  
  
_Source: mitre.org_  

### Detection

If you do not want to check the registry values one by one, you can return to the “Autoruns” tool.

![[reg2.png]]

  
Here, by opening the “Logon” and “Explorer” tabs, we can view the registry values that we have mentioned above. By checking the “Control Path” sections, we can check to see whether there is a suspicious file or not. If there are a high number of registry values in front of us, in order to save time, we can start by examining the registry values that do not have any values in the “Description” and “Publisher” sections.  
  
If you were not able to find the findings you wanted with autoruns, you can check the “Event Log”s, when a registry value is changed, an “EventID 4657” log is created. You can continue your analysis by filtering the security logs.  
  

### What Did We Learn?

- A user may manipulate the Startup file or the Registry values in order to run the requested file when a session is opened.
- We can track registry changes with EventID 4657
- We can detect suspicious Registry values with Autoruns


### Files

One of the most basic methods of maintaining persistence is to leave a malicious file within the system. This malicious file left in the system may aim to steal data from the file, open a backdoor, etc.  
  
Since there are a very large number of files within the system, it is impossible to check each one. Thus, there are two methods we can use.  

#### Manual Control

If we know the timeframe in which the incident occurred, we can list the files that have been created/organized during this timeframe and lower the number of files to be investigated.  
  
We can list the files that need to be investigated by choosing the timeframe of the event by use of the “Date modified” section that is located in the “Search” tab in “File Explorer”.


![[file1.png]]

  
In order to proceed more quickly through the results, we can start by primarily investigating the common extensions like “.bat” and “.exe”.  
  
The difficulty of this stage is the manual execution of proceed. However, AV evasion techniques will not work here, as it will be examined with the human eye.  

#### Automatic Control

With this method, we can use programs like AntiVirus or malware scanners to conduct a search within the entirety of the disk. Thus, both previous and newly created files will be automatically scanned.  
  
Since there will be no alert relating to malwares that have bypassed the AV, we cannot trust the scan to the extent of 100%.



### Additional Solutions

After all the examinations are complete, we want to make sure that everything is proceeding as normal after the incident that occurred. Thus, each machine that was affiliated with the incident, or in fact, if possible, all of the devices located in the network, should have an EDR agent (paid or open source) applied, and all of the data should be tracked in a central server.



![[img05234.png]]


  
Thus, all the devices will be controlled from a single point. Thanks to the rule sets applied in the EDR, if there is to be any suspicious activity continuing, an alarm will form, and you will be aware of the situation.  
  
The critical point here is the quality of the rule sets in the EDR. If you do not have rule sets that are able to detect suspicious activity, you will only be aware of basic activity that is occurring.


### Checklist


#### Tools That Can Be Used

- Process Hacker
- Autoruns
- FullEventLogView
- LastActivityView
- BrowsingHistoryView
  

#### Procedures That Must be Conducted for Memory Analysis

- Process Tree
- Web Connections
- Signature Status
  

#### Users

- Net user
- Lusrmgr.msc
- Event ID 4720 - A user account was created
- Event ID 4732 - A member was added to a security-enabled local group
  

#### Scheduled Tasks

- Autoruns, Event Viewer
- Event ID 4698 - A scheduled task was created
- Event ID 4702 - A scheduled task was updated
- Applications and Services Logs-Microsoft-Windows-TaskScheduler Operational.evtx
  

#### Services

  

#### Registry Run Keys / Startup Folder

- Event ID 4657: A registry value was modified
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
  

#### Files

- AV scan
- Manual Search