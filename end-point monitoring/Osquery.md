# osquery
Osquery is an open-source agent created by Facebook in 2014. It converts the operating system into a relational database. It allows us to ask questions from the tables using SQL queries, like returning the list of running processes, a user account created on the host, and the process of communicating with certain suspicious domains. It is widely used by Security Analysts, Incident Responders, Threat Hunters, etc. Osquery can be installed on multiple platforms: Windows, Linux, macOS, and FreeBSD.

## interactive mode 
One of the ways to interact with Osquery is by using the interactive mode. Open the terminal and run run `osqueryi`. To understand the tool, run the` .help `command in the interactive terminal, as shown below:
```
root@analyst$ osqueryi
Using a virtual database. Need help, type '.help'
osquery> .help
Welcome to the osquery shell. Please explore your OS!
You are connected to a transient 'in-memory' virtual database.

.all [TABLE]     Select all from a table
.bail ON|OFF     Stop after hitting an error
.connect PATH    Connect to an osquery extension socket
.disconnect      Disconnect from a connected extension socket
.echo ON|OFF     Turn command echo on or off
.exit            Exit this program
.features        List osquery's features and their statuses
.headers ON|OFF  Turn display of headers on or off
.help            Show this message
.mode MODE       Set output mode where MODE is one of:
                   csv      Comma-separated values
                   column   Left-aligned columns see .width
                   line     One value per line
                   list     Values delimited by .separator string
                   pretty   Pretty printed SQL results (default)
.nullvalue STR   Use STRING in place of NULL values
.print STR...    Print literal STRING
.quit            Exit this program
.schema [TABLE]  Show the CREATE statements
.separator STR   Change separator used by output mode
.socket          Show the local osquery extensions socket path
.show            Show the current values for various settings
.summary         Alias for the show meta command
.tables [TABLE]  List names of tables
.types [SQL]     Show result of getQueryColumns for the given query
.width [NUM1]+   Set column widths for "column" mode
.timer ON|OFF      Turn the CPU timer measurement on or off
```

## list tables
List the tables

To list all the available tables that can be queried, use the` .tables `meta-command.
```
osquery> .tables
  => appcompat_shims
  => arp_cache
  => atom_packages
  => authenticode
  => autoexec
  => azure_instance_metadata
  => azure_instance_tags
  => background_activities_moderator
  => bitlocker_info
  => carbon_black_info
  => carves
  => certificates
  => chassis_info
  => chocolatey_packages
  => chrome_extension_content_scripts
  => chrome_extensions
  => connectivity
  => cpu_info
  => cpuid
  => curl
  => curl_certificate
  => default_environment
  => device_file
  => device_hash
  => device_parti
```

To list all the tables with the term user in them, we will use .tables user

## Understanding the table Schema
Table names are not enough to know what information it contains without actually querying it. Knowledge of columns and types (known as a schema ) for each table is also helpful. 

We can list a table's schema with the following meta-command: `.schema table_name`

Display Mode

Osquery comes with multiple display modes to select from. Use the .help option to list the available modes or choose 1 of them as shown below:
```
root@analyst$ osqueryi
Using a virtual database. Need help, type '.help'
osquery>.help
Welcome to the osquery shell. Please explore your OS!
You are connected to a transient 'in-memory' virtual database.
.
.
.
.mode MODE       Set output mode where MODE is one of:
                   csv      Comma-separated values
                   column   Left-aligned columns see .width
                   line     One value per line
                   list     Values delimited by .separator string
                   pretty   Pretty printed SQL results (default)
```

## Schema Documentation
[scheama documentation for reference](https://osquery.io/schema/5.5.1/)
## creating sql queries

### Exploring Installed Programs
If you wish to retrieve all the information about the installed programs on the endpoint, first understand the table schema either using the .schema programs command in the interactive mode
Query: `SELECT * FROM programs LIMIT 1;`
```
root@analyst$ osqueryi
Using a virtual database. Need help, type '.help'
osquery>select * from programs limit 1;
              name = 7-Zip 21.07 (x64)
           version = 21.07
  install_location = C:\Program Files\7-Zip\
    install_source =
          language =
         publisher = Igor Pavlov
  uninstall_string = "C:\Program Files\7-Zip\Uninstall.exe"
      install_date =
identifying_number =
```
In the above example` LIMIT` was used followed by the number to limit the results to display.

The number of columns returned might be more than what you need. You can select specific columns rather than retrieve every column in the table. 

Query : 

```
SELECT name, version, install_location, install_date from programs limit 1;
```

### cout 
To see how many programs or entries in any table are returned, we can use the count() function, as shown below:
```
Query : SELECT count(*) from programs;
```
--osquery interactive mode--
```
root@analyst$ osqueryi
Using a virtual database. Need help, type '.help'
osquery>select count(*) from programs;
count(*) = 160
```

WHERE Clause

Optionally, you can use a WHERE clause to narrow down the list of results returned based on specified criteria. The following query will first get the user table and only display the result for the user James, as shown below:
Query : `SELECT * FROM users WHERE username='James';`
```
root@analyst$ osqueryi
Using a virtual database. Need help, type '.help'
osquery>SELECT * FROM users WHERE username='James';
        uid = 1002
        gid = 544
 uid_signed = 1002
 gid_signed = 544
   username = James
description =
  directory = C:\Users\James
      shell = C:\Windows\system32\cmd.exe
       uuid = S-1-5-21-605937711-2036809076-574958819-1002
       type = local
```

The equal sign is not the only filtering option in a WHERE clause. Below are filtering operators that can be used in a WHERE clause:

 

 
- 
- = [equal]
- <>  [not equal]
- '' > , >='' [greater than, greater than, or equal to]
- < , <= [less than or less than or equal to] 
- BETWEEN [between a range]
- LIKE [pattern wildcard searches]
- % [wildcard, multiple characters]
- _ [wildcard, one character]
Matching Wildcard Rules

Below is a screenshot from the Osquery documentation showing examples of using wildcards when used in folder structures:
```

% : Match all files and folders for one level.
%% : Match all files and folders recursively.
%abc : Match all within-level ending in "abc".
abc% : Match all within-level starting with "abc".
```
Matching Examples
```
/Users/%/Library : Monitor for changes to every user's Library folder, but not the contents within .
/Users/%/Library/ : Monitor for changes to files within each Library folder, but not the contents of their subdirectories.
/Users/%/Library/% : Same, changes to files within each Library folder.
/Users/%/Library/%% : Monitor changes recursively within each Library.
/bin/%sh : Monitor the bin directory for changes ending in sh .
```

## Joining Tables using JOIN Function

OSquery can also be used to join two tables based on a column that is shared by both tables. Let's look at two tables to demonstrate this further. Below is the schema for the user's table and the processes table. 
```
root@analyst$ osqueryi
Using a virtual database. Need help, type '.help'
osquery>.schema users
CREATE TABLE users(`uid` BIGINT, `gid` BIGINT, `uid_signed` BIGINT, `gid_signed` BIGINT, `username` TEXT, `description` TEXT, `directory` TEXT, `shell` TEXT, `uuid` TEXT, `type` TEXT, `is_hidden` INTEGER HIDDEN, `pid_with_namespace` INTEGER HIDDEN, PRIMARY KEY (`uid`, `username`, `uuid`, `pid_with_namespace`)) WITHOUT ROWID;

osquery>.schema processes
CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `path` TEXT, `cmdline` TEXT, `state` TEXT, `cwd` TEXT, `root` TEXT, `uid` BIGINT, `gid` BIGINT, `euid` BIGINT, `egid` BIGINT, `suid` BIGINT, `sgid` BIGINT, `on_disk` INTEGER, `wired_size` BIGINT, `resident_size` BIGINT, `total_size` BIGINT, `user_time` BIGINT, `system_time` BIGINT, `disk_bytes_read` BIGINT, `disk_bytes_written` BIGINT, `start_time` BIGINT, `parent` BIGINT, `pgroup` BIGINT, `threads` INTEGER, `nice` INTEGER, `elevated_token` INTEGER, `secure_process` INTEGER, `protection_type` TEXT, `virtual_process` INTEGER, `elapsed_time` BIGINT, `handle_count` BIGINT, `percent_processor_time` BIGINT, `upid` BIGINT HIDDEN, `uppid` BIGINT HIDDEN, `cpu_type` INTEGER HIDDEN, `cpu_subtype` INTEGER HIDDEN, `translated` INTEGER HIDDEN, `cgroup_path` TEXT HIDDEN, `phys_footprint` BIGINT HIDDEN, PRIMARY KEY (`pid`)) WITHOUT ROWID;
     
```

Looking at both schemas, uid in users table is meant to identify the user record, and in the processes table, the column uid represents the user responsible for executing the particular process. We can join both tables using this uid field as shown below:

Query1: select uid, pid, name, path from processes;

Query2: select uid, username, description from users;

Joined Query: `select p.pid, p.name, p.path, u.username from processes p JOIN users u on u.uid=p.uid LIMIT 10;`
	```
	root@analyst$ osqueryi
	Using a virtual database. Need help, type '.help'
	osquery>select p.pid, p.name, p.path, u.username from processes p JOIN users u on u.uid=p.uid LIMIT 10;
	+-------+-------------------+---------------------------------------+----------+
	| pid   | name              | path                                  | username |
	+-------+-------------------+---------------------------------------+----------+
	| 7560  | sihost.exe        | C:\Windows\System32\sihost.exe        | James    |
	| 6984  | svchost.exe       | C:\Windows\System32\svchost.exe       | James    |
	| 7100  | svchost.exe       | C:\Windows\System32\svchost.exe       | James    |
	| 7144  | svchost.exe       | C:\Windows\System32\svchost.exe       | James    |
	| 8636  | ctfmon.exe        | C:\Windows\System32\ctfmon.exe        | James    |
	| 8712  | taskhostw.exe     | C:\Windows\System32\taskhostw.exe     | James    |
	| 9260  | svchost.exe       | C:\Windows\System32\svchost.exe       | James    |
	| 10168 | RuntimeBroker.exe | C:\Windows\System32\RuntimeBroker.exe | James    |
	| 10232 | RuntimeBroker.exe | C:\Windows\System32\RuntimeBroker.exe | James    |
	| 8924  | svchost.exe       | C:\Windows\System32\svchost.exe       | James    |
	+-------+-------------------+---------------------------------------+----------+
	      
	```