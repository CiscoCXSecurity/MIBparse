#!/usr/bin/perl -w 

# MIBparse.pl - Offline SNMP MIB parser tool for Linux
# Copyright (C) 2008 Faisal Dean (Faiz)
# 
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# do not use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# You are encouraged to send comments, improvements or suggestions to
# me at fmd@portcullis-security.com

#########################################################################
# Filename:        MIBparse.pl                                          #
# Written by:      Faiz                                                 #
# Version:         0.1.1                                                #
#########################################################################

#########################################################################
# Software Requirements:                                                #
#       Perl                                                            #
#	<dictionary file>                                               #
#########################################################################

#########################################################################
# Description:                                                          #
#                                                                       #
# Takes as an argument, a text file containing                          #
# an SNMP MIB and parses it revealing the juicy info.                   #
# The tool will take a raw snmpwalk output, whether this be from        #
# the snmpwalk tool or another tool which provides similar output       #
#########################################################################

#########################################################################
# Execution modes:                                                      #
#                                                                       #
# The following method of execution will take the tags file as a custom #
# tags file perform the operations defined by -a option, in this        #
# instance, displaying the users:                                       #
#                                                                       #
# ./MIBparse.pl -f public.txt -a 7 -b ./tags-alternate                  #
#                                                                       #
# The following mode of execution relies on the fact that the tags file #
# has been copied to the /usr/local/bin/ directory:                     #
#                                                                       #
# ./MIBparse.pl -f public.txt -a 7                                      #
#                                                                       #
#########################################################################

use Getopt::Std;
use IO::Socket;
use Term::ANSIColor;

use vars qw($MIBFILE $DICTFILE $mibfile $dictfile $checkFile $specificType $typeScan);

$mibfile = 0;	#this is a flag used for validation purposes 
$typeScan = 0;	#this is a a boolean flag for the type scan
$DICTFILE = "/usr/local/bin/tags";

#main
{
	print color("green"), "\nMIBparse.pl v0.1.1 - By Faiz \n\n", color("reset");
	
	my(@juicyStuff, $MIBFILE, @MIBfilecontent);

	getopts("f:a:b:");

	if($opt_f)
	{
		$MIBFILE = $opt_f;
		$mibfile = 1;
	}
	elsif(!$opt_a && !$opt_f && !$opt_b)
	{
		usage();
		exitProgram();
	}
	if($opt_a)
	{
		if($opt_a == 1)
		{
			$typeScan = 0;
		}
		elsif($opt_a == 2)
		{
			#use system tags file
			$specificType = "system"; 	
			$typeScan = 1;
		}
		elsif($opt_a == 3)
		{
			#use routing tags file
			$specificType = "routing"; 	
			$typeScan = 1;
		}
		elsif($opt_a == 4)
		{
			#use services tags file
			$specificType = "services"; 	
			$typeScan = 1;
		}
		elsif($opt_a == 5)
		{
			#use tcp tags file
			$specificType = "tcp"; 	
			$typeScan = 1;
		}
		elsif($opt_a == 6)
		{
			#use udp tags file
			$specificType = "udp"; 	
			$typeScan = 1;
		}
		elsif($opt_a == 7)
		{
			#use users tags file
			$specificType = "users"; 	
			$typeScan = 1;
		}
		elsif($opt_a == 8)
		{
			#use shares tags file
			$specificType = "shares"; 	
			$typeScan = 1;
		}
		elsif($opt_a == 9)
		{
			#use domain tags file
			$specificType = "domain"; 	
			$typeScan = 1;
		}
		elsif($opt_a == 10)
		{
			#use domain tags file
			$specificType = "installed"; 	
			$typeScan = 1;
		}
		elsif($opt_a == 11)
		{
			#use domain tags file
			$specificType = "community"; 	
			$typeScan = 1;
		}
		else
		{
			print"\nNo such tag file value....Exiting program\n";
			exitProgram();
		}
		
	}
	if($opt_b)
	{
		#use custom tags file
		$DICTFILE = $opt_b;
	}
	if($mibfile == 1)
	{ 
		@juicyStuff = parseFile(@MIBfilecontent = fileAccess($MIBFILE)); 	 

	}
	else
	{
		usage();
		exitProgram();
	} 
}
		
sub usage {
	
	print color("green"), "Description:\n";
	print "Parsing tool for 'snmpwalk' output.\n";
	print "Takes the snmpwalk output as a file\n";
	print "displaying any useful information.\n", color("reset");
        print "\n\nUsage = ./MIBparse.pl -f <Offline MIB file> [optional]\n\n";
        print " -f [file containing the snmpwalk output]\n";

        print "\nOptional:\n";
        print " -a [value]\n";
	print "	Where 'value' is one of the following:\n";
	print "	1 = All\n";
	print "	2 = System\n";
	print "	3 = Routing information\n";
	print "	4 = Services\n";
	print "	5 = TCP ports\n";
	print "	6 = UDP ports\n";
	print "	7 = Users\n";
	print "	8 = Shares\n";
	print "	9 = Domain\n";
	print "	10 = Installed components\n";
	print "	11 = Community strings\n";
	print " -b [custom tags file]\n";

        exitProgram();
}

sub fileAccess {
    my (@CONTENT);
    open(U,"<$_[0]") or die "Cannot open $_[0]";
    @CONTENT = <U>;
    close(U);

    return @CONTENT;
}

sub parseFile {
	my(@MIBcontent, @DICTcontent, $dict, @dict2, $mib, @mib2, $tag, $desc, $important, $spacing, $count, $type);
	
	#assign the MIB file passed to the function to a temporary array
	@MIBcontent = @_;
	
	#readin the dictionary file from disk
	@DICTcontent = fileAccess($DICTFILE);

	
	#if '@mibdata' is still empty, there is no usefull information 
	#in the MIB output file provided by the user. Or, the file is empty 
	
	if (not @MIBcontent) 
	{
		print "\nThere is no useful information in the MIB file \n";
		print "AND/OR\n";
		print "This is not a MIB output file...\n";
		print "AND/OR\n";
		print "This is an empty file....\n";
		exitProgram();
	}

	#if the tags file is empty
	if (not @DICTcontent) 
	{
		print "\nThe Dictionary file is empty \n";
		exitProgram();
	}

	#if the tags file is not empty	
	foreach $dict (@DICTcontent)
	{

		#reset counter
		$count = 0;
		#for every line in the MIB file
		foreach $mib (@MIBcontent)
		{
			#use the comma is a delimeter
			@dict2 = split(/,/, $dict);
			$type = $dict2[0];		#type, for type scans
			$tag = $dict2[1];		#the tag to be matched with the contents of the MIB file line
			$desc = $dict2[2];		#the description of the value of the MIB line

			#if type scanning is selected by the user
			if($typeScan == 1)
			{
				if($type eq $specificType)
				{
					#if the tag exists on the line of the MIB that is being parsed	
					if ($mib =~ /$tag/)
					{
						#responsible for the spacing in the output
						$count = $count + 1;
						#extract important info from the line in the MIB file
						@mib2 = split(/= /, $mib);
						$important = $mib2[1];
						chomp($desc);		
						
						#try to identify if the retuned field is blank
						chomp($important);
						
						if ($important)
						{
							#print the formated info
							print "  $count.	";
							print color("yellow"), "$desc", color("reset");
							print color("white"), "$important\n", color("reset");
							$spacing = 1;
						}
					}
				}
			}
			else
			{
				#if the tag exists on the line of the MIB that is being parsed	
				if ($mib =~ /$tag/)
				{
					#responsible for the spacing in the output
					$count = $count + 1;
					#extract important info from the line in the MIB file
					@mib2 = split(/= /, $mib);
					$important = $mib2[1];
					chomp($desc);		
					
					#try to identify if the retuned field is blank
					chomp($important);
					
					if ($important)
					{
						#print the formated info
						print "  $count.	";
						print color("yellow"), "$desc", color("reset");
						print color("white"), "$important\n", color("reset");
						$spacing = 1;
					}
				}
			}
		}
		#this ensures that the spacing is correct
		if ($spacing)
		{
			print"\n";
			$spacing = 0;
		}
	}
}

sub exitProgram {
	print "\n\n";
	exit();
}
