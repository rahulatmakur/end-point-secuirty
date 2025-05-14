# SYSMON
Sysmon, a tool used to monitor and log events on Windows, is commonly used by enterprises as part of their monitoring and logging solutions. Part of the Windows Sysinternals package, Sysmon is similar to Windows Event Logs with further detail and granular control.

Sysmon gathers detailed and high-quality logs as well as event tracing that assists in identifying anomalies in your environment. Sysmon is most commonly used in conjunction with security information and event management (SIEM) system or other log parsing solutions that aggregate, filter, and visualize events. When installed on an endpoint, Sysmon will start early in the Windows boot process. In an ideal scenario, the events would be forwarded to a SIEM for further analysis. 

Events within Sysmon are stored in Applications and Services `Logs/Microsoft/Windows/Sysmon/Operational`

## Sysmon Config Overview
Sysmon requires a config file in order to tell the binary how to analyze the events that it is receiving. You can create your own Sysmon config or you can download a config

Sysmon includes 29 different types of Event IDs, all of which can be used within the config to specify how the events should be handled and analyzed.

	Note: As there are so many Event IDs Sysmon analyzes. we will only be going over a few of the ones that we think are most important to understand.

### Event ID 1: Process Creation

This event will look for any processes that have been created. You can use this to look for known suspicious processes or processes with typos that would be considered an anomaly. This event will use the CommandLine and Image XML tags.
```
<RuleGroup name="" groupRelation="or">
	<ProcessCreate onmatch="exclude">
	 	<CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>
	</ProcessCreate>
</RuleGroup>
```

The above code snippet is specifying the Event ID to pull from as well as what condition to look for. In this case, it is excluding the svchost.exe process from the event logs.

### Event ID 3: Network Connection

The network connection event will look for events that occur remotely. This will include files and sources of suspicious binaries as well as opened ports. This event will use the Image and DestinationPort XML tags. 
```
<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
	 	<Image condition="image">nmap.exe</Image>
	 	<DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>
	</NetworkConnect>
</RuleGroup>

```

The above code snippet includes two ways to identify suspicious network connection activity. The first way will identify files transmitted over open ports. In this case, we are specifically looking for nmap.exe which will then be reflected within the event logs. The second method identifies open ports and specifically port 4444 which is commonly used with Metasploit. If the condition is met an event will be created and ideally trigger an alert for the SOC to further investigate.

### Event ID 7: Image Loaded

This event will look for DLLs loaded by processes, which is useful when hunting for DLL Injection and DLL Hijacking attacks. It is recommended to exercise caution when using this Event ID as it causes a high system load. This event will use the Image, Signed, ImageLoaded, and Signature XML tags. 

```
<RuleGroup name="" groupRelation="or">
	<ImageLoad onmatch="include">
	 	<ImageLoaded condition="contains">\Temp\</ImageLoaded>
	</ImageLoad>
</RuleGroup>
```


The above code snippet will look for any DLLs that have been loaded within the \Temp\ directory. If a DLL is loaded within this directory it can be considered an anomaly and should be further investigateded. 

### Event ID 8: CreateRemoteThread

The CreateRemoteThread Event ID will monitor for processes injecting code into other processes. The CreateRemoteThread function is used for legitimate tasks and applications. However, it could be used by malware to hide malicious activity. This event will use the SourceImage, TargetImage, StartAddress, and StartFunction XML tags.

```
<RuleGroup name="" groupRelation="or">
	<CreateRemoteThread onmatch="include">
	 	<StartAddress name="Alert,Cobalt Strike" condition="end with">0B80</StartAddress>
	 	<SourceImage condition="contains">\</SourceImage>
	</CreateRemoteThread>
</RuleGroup>

```

The above code snippet shows two ways of monitoring for CreateRemoteThread. The first method will look at the memory address for a specific ending condition which could be an indicator of a Cobalt Strike beacon. The second method will look for injected processes that do not have a parent process. This should be considered an anomaly and require further investigation. 

### Event ID 11: File Created

This event ID is will log events when files are created or overwritten the endpoint. This could be used to identify file names and signatures of files that are written to disk. This event uses TargetFilename XML tags.
```
<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
	 	<TargetFilename name="Alert,Ransomware" condition="contains">HELP_TO_SAVE_FILES</TargetFilename>
	</FileCreate>
</RuleGroup> 
```

The above code snippet is an example of a ransomware event monitor. This is just one example of a variety of different ways you can utilize Event ID 11.

### Event ID 12 / 13 / 14: Registry Event

This event looks for changes or modifications to the registry. Malicious activity from the registry can include persistence and credential abuse. This event uses TargetObject XML tags.

```
<RuleGroup name="" groupRelation="or">
	<RegistryEvent onmatch="include">
	 	<TargetObject name="T1484" condition="contains">Windows\System\Scripts</TargetObject>
	</RegistryEvent>
</RuleGroup>
```

The above code snippet will look for registry objects that are in the "Windows\System\Scripts" directory as this is a common directory for adversaries to place scripts to establish persistence.

### Event ID 15: FileCreateStreamHash

This event will look for any files created in an alternate data stream. This is a common technique used by adversaries to hide malware. This event uses TargetFilename XML tags.

```
<RuleGroup name="" groupRelation="or">
	<FileCreateStreamHash onmatch="include">
	 	<TargetFilename condition="end with">.hta</TargetFilename>
	</FileCreateStreamHash>
</RuleGroup> 

```
The above code snippet will look for files with the .hta extension that have been placed within an alternate data stream.

### Event ID 22: DNS Event

This event will log all DNS queries and events for analysis. The most common way to deal with these events is to exclude all trusted domains that you know will be very common "noise" in your environment. Once you get rid of the noise you can then look for DNS anomalies. This event uses QueryName XML tags. 

```
<RuleGroup name="" groupRelation="or">
	<DnsQuery onmatch="exclude">
	 	<QueryName condition="end with">.microsoft.com</QueryName>
	</DnsQuery>
</RuleGroup> 
```

The above code snippet will get exclude any DNS events with the .microsoft.com query. This will get rid of the noise that you see within the environment.  

### Sysmon "Best Practices"
Sysmon offers a fairly open and configurable platform for you to use. Generally speaking, there are a few best practices that you could implement to ensure you're operating efficiently and not missing any potential threats. A few common best practices are outlined and explained below.

Exclude > Include

When creating rules for your Sysmon configuration file it is typically best to prioritize excluding events rather than including events. This prevents you from accidentally missing crucial events and only seeing the events that matter the most.

CLI gives you further control

As is common with most applications the CLI gives you the most control and filtering allowing for further granular control. You can use either Get-WinEvent or wevutil.exe to access and filter logs. As you incorporate Sysmon into your SIEM or other detection solutions these tools will become less used and needed. 

Know your environment before implementation

Knowing your environment is important when implementing any platform or tool. You should have a firm understanding of the network or environment you are working within to fully understand what is normal and what is suspicious in order to effectively craft your rule

To filter out the logs we nned to use the applications like the wevtutil or event viewer which have been disscused in the win log file.
## Hunting Network Connections  

We will first be looking at a modified Ion-Security configuration to detect the creation of new network connections. The code snippet below will use event ID 3 along with the destination port to identify active connections specifically connections on port 4444 and 5555. 

```
<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
		<DestinationPort condition="is">4444</DestinationPort>
		<DestinationPort condition="is">5555</DestinationPort>
	</NetworkConnect>
</RuleGroup>

```

## Hunting for Open Ports with PowerShell

To hunt for open ports with PowerShell we will be using the PowerShell module Get-WinEvent along with XPath queries. We can use the same  XPath queries that we used in the rule to filter out events from NetworkConnect with DestinationPort. The command line is typically used over the Event Viewer GUI because it can allow for further granular control and filtering that the GUI does not offer. For more information about using XPath and the command line for event viewing, check out the Windows Event Log room by Heavenraiza.

`Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'`

## Detecting Mimikatz Overview

Mimikatz is well known and commonly used to dump credentials from memory along with other Windows post-exploitation activity. Mimikatz is mainly known for dumping LSASS. We can hunt for the file created, execution of the file from an elevated process, creation of a remote thread, and processes that Mimikatz creates. Anti-Virus will typically pick up Mimikatz as the signature is very well known but it is still possible for threat actors to obfuscate or use droppers to get the file onto the device. For this hunt, we will be using a custom configuration file to minimize network noise and focus on the hunt. 

## Detecting File Creation

The first method of hunting for Mimikatz is just looking for files created with the name Mimikatz. This is a simple technique but can allow you to find anything that might have bypassed AV. Most of the time when dealing with an advanced threat you will need more advanced hunting techniques like searching for LSASS behavior but this technique can still be useful. 

This is a very simple way of detecting Mimikatz activity that has bypassed anti-virus or other detection measures. But most of the time it is preferred to use other techniques like hunting for LSASS specific behavior. Below is a snippet of a config to aid in the hunt for Mimikatz. 

```
<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
		<TargetFileName condition="contains">mimikatz</TargetFileName>
	</FileCreate>
</RuleGroup>
```

## Hunting Abnormal LSASS Behavior

We can use the ProcessAccess event ID to hunt for abnormal LSASS behavior. This event along with LSASS would show potential LSASS abuse which usually connects back to Mimikatz some other kind of credential dumping tool. Look below for more detail on hunting with these techniques.

If LSASS is accessed by a process other than svchost.exe it should be considered suspicious behavior and should be investigated further, to aid in looking for suspicious events you can use a filter to only look for processes besides svchost.exe. Sysmon will provide us further details to help lead the investigation such as the file path the process originated from. To aid in detections we will be using a custom configuration file. Below is a snippet of the config that will aid in the hunt.

```

<RuleGroup name="" groupRelation="or">
	<ProcessAccess onmatch="include">
	       <TargetImage condition="image">lsass.exe</TargetImage>
	</ProcessAccess>
</RuleGroup>

````

We see the event that has the Mimikatz process accessed but we also see a lot of svchost.exe events? We can alter our config to exclude events with the SourceImage event coming from svhost.exe. Look below for a modified configuration rule to cut down on the noise that is present in the event logs.

```
<RuleGroup name="" groupRelation="or">
	<ProcessAccess onmatch="exclude">
		<SourceImage condition="image">svchost.exe</SourceImage>
	</ProcessAccess>
	<ProcessAccess onmatch="include">
		<TargetImage condition="image">lsass.exe</TargetImage>
	</ProcessAccess>
</RuleGroup>
 
```

## Hunting Malware Overview

Malware has many forms and variations with different end goals. The two types of malware that we will be focusing on are RATs and backdoors. RATs or Remote Access Trojans are used similar to any other payload to gain remote access to a machine. RATs typically come with other Anti-Virus and detection evasion techniques that make them different than other payloads like MSFVenom. A RAT typically also uses a Client-Server model and comes with an interface for easy user administration. Examples of RATs are Xeexe and Quasar. To help detect and hunt malware we will need to first identify the malware that we want to hunt or detect and identify ways that we can modify configuration files, this is known as hypothesis-based hunting. There are of course a plethora of other ways to detect and log malware however we will only be covering the basic way of detecting open back connect ports. 

### Hunting Rats and C2 Servers

The first technique we will use to hunt for malware is a similar process to hunting Metasploit. We can look through and create a configuration file to hunt and detect suspicious ports open on the endpoint. By using known suspicious ports to include in our logs we can add to our hunting methodology in which we can use logs to identify adversaries on our network then use packet captures or other detection strategies to continue the investigation. The code snippet below is from the Ion-Storm configuration file which will alert when specific ports like 1034 and 1604 as well as exclude common network connections like OneDrive, by excluding events we still see everything that we want without missing anything and cutting down on noise. 

When using configuration files in a production environment you must be careful and understand exactly what is happening within the configuration file an example of this is the Ion-Storm configuration file excludes port 53 as an event. Attackers and adversaries have begun to use port 53 as part of their malware/payloads which would go undetected if you blindly used this configuration file as-is.

For more information about the ports that this configuration file alerts on check out this spreadsheet.

```
<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
		<DestinationPort condition="is">1034</DestinationPort>
		<DestinationPort condition="is">1604</DestinationPort>
	</NetworkConnect>
	<NetworkConnect onmatch="exclude">
		<Image condition="image">OneDrive.exe</Image>
	</NetworkConnect>
</RuleGroup>

```

## Hunting for Common Back Connect Ports with PowerShell

Just like previous sections when using PowerShell we will again be using the PowerShell module Get-WinEvent along with XPath queries to filter our events and gain granular control over our logs. We will need to filter on the NetworkConnect event ID and the DestinationPort data attribute. If you're using a good configuration file with a reliable set of rules it will do a majority of the heavy lifting and filtering to what you want should be easy.

`Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=<Port>'`

## Persistence Overview

Persistence is used by attackers to maintain access to a machine once it is compromised. There is a multitude of ways for an attacker to gain persistence on a machine. We will be focusing on registry modification as well as startup scripts. We can hunt persistence with Sysmon by looking for File Creation events as well as Registry Modification events. The SwiftOnSecurity configuration file does a good job of specifically targeting persistence and techniques used. You can also filter by the Rule Names in order to get past the network noise and focus on anomalies within the event logs. 

You can download the event logs used in this room from this task or you can open them in the Practice folder on the provided machine.

## Hunting Startup Persistence

We will first be looking at the SwiftOnSecurity detections for a file being placed in the \Startup\ or \Start Menu directories. Below is a snippet of the config that will aid in event tracing for this technique. For more information about this technique check out MITRE ATT&CK T1547.

```
<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
		<TargetFilename name="T1023" condition="contains">\Start Menu</TargetFilename>
		<TargetFilename name="T1165" condition="contains">\Startup\</TargetFilename>
	</FileCreate>
</RuleGroup>

```

## Hunting Registry Key Persistence

We will again be looking at another SwiftOnSecurity detection this time for a registry modification that adjusts that places a script inside CurrentVersion\Windows\Run and other registry locations. For more information about this technique check out MITRE ATT&CK T1112.

```
<RuleGroup name="" groupRelation="or">
	<RegistryEvent onmatch="include">
		<TargetObject name="T1060,RunKey" condition="contains">CurrentVersion\Run</TargetObject>
		<TargetObject name="T1484" condition="contains">Group Policy\Scripts</TargetObject>
		<TargetObject name="T1060" condition="contains">CurrentVersion\Windows\Run</TargetObject>
	</RegistryEvent>
</RuleGroup>
```

## Evasion Techniques Overview

There are a number of evasion techniques used by malware authors to evade both anti-virus and detections. Some examples of evasion techniques are Alternate Data Streams, Injections, Masquerading, Packing/Compression, Recompiling, Obfuscation, Anti-Reversing Techniques. In this task, we will be focusing on Alternate Data Streams and Injections. Alternate Data Streams are used by malware to hide its files from normal inspection by saving the file in a different stream apart from $DATA. Sysmon comes with an event ID to detect newly created and accessed streams allowing us to quickly detect and hunt malware that uses ADS. Injection techniques come in many different types: Thread Hijacking, PE Injection, DLL Injection, and more. In this room, we will be focusing on DLL Injection and backdooring DLLs. This is done by taking an already used DLL that is used by an application and overwriting or including your malicious code within the DLL.
## Hunting Alternate Data Streams

The first technique we will be looking at is hiding files using alternate data streams using Event ID 15. Event ID 15 will hash and log any NTFS Streams that are included within the Sysmon configuration file. This will allow us to hunt for malware that evades detections using ADS. To aid in hunting ADS we will be using the SwiftOnSecurity Sysmon configuration file. The code snippet below will hunt for files in the Temp and Startup folder as well as .hta and .bat extension.

```
<RuleGroup name="" groupRelation="or">
	<FileCreateStreamHash onmatch="include">
		<TargetFilename condition="contains">Downloads</TargetFilename>
		<TargetFilename condition="contains">Temp\7z</TargetFilename>
		<TargetFilename condition="ends with">.hta</TargetFilename>
		<TargetFilename condition="ends with">.bat</TargetFilename>
	</FileCreateStreamHash>
</RuleGroup>
```

