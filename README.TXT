MIBparse.pl - Offline SNMP MIB parser tool for Linux
Copyright (C) 2008 Faisal Dean (Faiz)

This tool can be executed from any working directory, but care must be taken to ensure that the "tags" dictionary file is present in either "/usr/local/bin" or is specified at the command line using the "-b" optional flag.

The tool is designed to quickly parse output from SNMP tools such as snmpwalk from the NET-SNMP project "net-snmp.sourceforge.net". It references the tags within the "tags" file. The tags are comma separated values that represent the "type", "tag" and "description" for each item that is to be searched within the SNMP output generated by other tools.

Why code such a tool?
Well, SNMP is a very useful source for information if you know what to look for. I got sick of parsing very large MIB files and as a result wanted a tool that could parse the output for me (offline). There was nothing available at the time, as all the tools required access to the server offering the SNMP service to work, so I decided to code a simple engine using the bash shell. It quickly became more than just a simple script, so I decided to write it in Perl.

There are many modes of execution. The following examples will attempt to define some of the ways that the tool can be used:

The simplest way to run the tool is as follows:

./MIBparse -f public.txt

Where "public.txt" is the output from snmpwalk piped to a file. This mode of execution requires the "tags" file to be present in the "/usr/local/bin" directory. If this is not the case then the tool will fail. In this mode all available information is displayed to the user as standard out.

The information that is output can be tailored using the "-a" flag. The following values can be used in conjunction with this flag:
        1 = All
        2 = System
        3 = Routing information
        4 = Services
        5 = TCP ports
        6 = UDP ports
        7 = Users
        8 = Shares
        9 = Domain
        10 = Installed components
        11 = Community strings
Each value corresponds to the type of information that is output. As an example, "-a 7" will output all of the users from a Windows system. The example execution in this case would include:

./MIBparse.pl -f public.txt -a 7

If you wish to execute the tool from a working directory which is not in your $PATH then the "-b" option can be used to specify the location of the "tags" file. This option can also be used to specify any file as a tags file as long as the format of the file conforms to the example that is provided. The example execution in such a case would be:

./MIBparse.pl -f public.txt -b ./tags
OR
./MIBparse.pl -f public.txt -b ./mytagsfile

Finally, the "-b" flag can be used in conjunction with the "-a" flag. The example execution in such a case would be:

./MIBparse.pl -f public.txt -b ./mytagsfile -a 7

Any comments can be emailed to me at:

fmd@portcullis-security.com
