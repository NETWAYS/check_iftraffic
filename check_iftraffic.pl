#!/usr/bin/perl -w
#
# check_iftraffic.pl - Nagios(r) network traffic monitor plugin
# Copyright (C) 2004 Gerd Mueller / Netways GmbH
# $Id: check_iftraffic.pl 1119 2006-02-09 10:30:09Z gmueller $
#
# mw = Markus Werner mw+nagios@wobcom.de
# Remarks (mw):
#
#	I adopted as much as possible the programming style of the origin code.
#
#	There should be a function to exit this programm,
#	instead of calling print and exit statements all over the place.
#
#
# minor changes by mw
# 	The snmp if_counters on net devices can have overflows.
#	I wrote this code to address this situation.
#	It has no automatic detection and which point the overflow
#	occurs but it will generate a warning state and you
#	can set the max value by calling this script with an additional
#	arg.
#
# minor cosmetic changes by mw
#	Sorry but I couldn't sustain to clean up some things.
#
# based on check_traffic from Adrian Wieczorek, <ads (at) irc.pila.pl>
#
# Send us bug reports, questions and comments about this plugin.
# Latest version of this software: http://www.nagiosexchange.org
#
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307

use strict;

use Net::SNMP;
use Getopt::Long;
&Getopt::Long::config('bundling');

use Data::Dumper;

my $host_address;
my $iface_number;
my $iface_descr;
my $iface_speed;
my $opt_h;
my $units;

my $session;
my $error;
my $port         = 161;
my $snmp_version = 1;

my @snmpoids;

# SNMP OIDs for Traffic
my $snmpIfInOctets  = '1.3.6.1.2.1.2.2.1.10';
my $snmpIfOutOctets = '1.3.6.1.2.1.2.2.1.16';
my $snmpIfDescr     = '1.3.6.1.2.1.2.2.1.2';

my $response;

# Path to  tmp files
my $TRAFFIC_FILE = "/tmp/traffic";

my %STATUS_CODE =
  ( 'UNKNOWN' => '-1', 'OK' => '0', 'WARNING' => '1', 'CRITICAL' => '2' );

#default values;
my ( $in_bytes, $out_bytes ) = 0;
my $warn_usage = 85;
my $crit_usage = 98;
my $COMMUNITY  = "public";

#added 20050614 by mw
my $max_value;
my $max_bytes;

#cosmetic changes 20050614 by mw, see old versions for detail
my $status = GetOptions(
	"h|help"        => \$opt_h,
	"C|community=s" => \$COMMUNITY,
	"w|warning=s"   => \$warn_usage,
	"c|critical=s"  => \$crit_usage,
	"b|bandwidth=i" => \$iface_speed,
	"p|port=i"      => \$port,
	"u|units=s"     => \$units,
	"i|interface=s" => \$iface_descr,
	"H|hostname=s"  => \$host_address,

	#added 20050614 by mw
	"M|max=i" => \$max_value
);

if ( $status == 0 ) {
	print_help();
	exit $STATUS_CODE{'OK'};
}

if ( ( !$host_address ) or ( !$iface_descr ) or ( !$iface_speed ) ) {
	print_usage();
}

#change 20050414 by mw
$iface_speed = bits2bytes( $iface_speed, $units ) / 1024;
if ( !$max_value ) {

	#if no -M Parameter was set, set it to 32Bit Overflow
	$max_bytes = 419304;    # the value is (2^32/1024)
}
else {
	$max_bytes = unit2bytes( $max_value, $units );
}

if ( $snmp_version =~ /[12]/ ) {
	( $session, $error ) = Net::SNMP->session(
		-hostname  => $host_address,
		-community => $COMMUNITY,
		-port      => $port,
		-version   => $snmp_version
	);

	if ( !defined($session) ) {
		print("UNKNOWN: $error");
		exit $STATUS_CODE{'UNKNOWN'};
	}
}
elsif ( $snmp_version =~ /3/ ) {
	my $state = 'UNKNOWN';
	print("$state: No support for SNMP v3 yet\n");
	exit $STATUS_CODE{$state};
}
else {
	my $state = 'UNKNOWN';
	print("$state: No support for SNMP v$snmp_version yet\n");
	exit $STATUS_CODE{$state};
}

$iface_number = fetch_ifdescr( $session, $iface_descr );

push( @snmpoids, $snmpIfInOctets . "." . $iface_number );
push( @snmpoids, $snmpIfOutOctets . "." . $iface_number );

if ( !defined( $response = $session->get_request(@snmpoids) ) ) {
	my $answer = $session->error;
	$session->close;

	print("WARNING: SNMP error: $answer\n");
	exit $STATUS_CODE{'WARNING'};
}

$in_bytes  = $response->{ $snmpIfInOctets . "." . $iface_number } / 1024;
$out_bytes = $response->{ $snmpIfOutOctets . "." . $iface_number } / 1024;

$session->close;

my $row;
my $last_check_time = time - 1;
my $last_in_bytes   = $in_bytes;
my $last_out_bytes  = $out_bytes;

if (
	open( FILE,
		"<" . $TRAFFIC_FILE . "_if" . $iface_number . "_" . $host_address
	)
  )
{
	while ( $row = <FILE> ) {

		#cosmetic change 20050416 by mw
		#Couldn't sustain;-)
		chomp();
		( $last_check_time, $last_in_bytes, $last_out_bytes ) =
		  split( ":", $row );
	}
	close(FILE);
}

my $update_time = time;

open( FILE, ">" . $TRAFFIC_FILE . "_if" . $iface_number . "_" . $host_address )
  or die "Can't open $TRAFFIC_FILE for writing: $!";
printf FILE ( "%s:%.0ld:%.0ld\n", $update_time, $in_bytes, $out_bytes );
close(FILE);

my $db_file;

#added 20050614 by mw
#Check for and correct counter overflow (if possible).
#See function counter_overflow.
$in_bytes  = counter_overflow( $in_bytes,  $last_in_bytes,  $max_bytes );
$out_bytes = counter_overflow( $out_bytes, $last_out_bytes, $max_bytes );

my $in_traffic = sprintf( "%.2lf",
	( $in_bytes - $last_in_bytes ) / ( time - $last_check_time ) );
my $out_traffic = sprintf( "%.2lf",
	( $out_bytes - $last_out_bytes ) / ( time - $last_check_time ) );

my $in_traffic_absolut  = sprintf( "%.0d", $last_in_bytes );
my $out_traffic_absolut = sprintf( "%.0d", $last_out_bytes );

my $in_usage  = sprintf( "%.1f", ( 1.0 * $in_traffic * 100 ) / $iface_speed );
my $out_usage = sprintf( "%.1f", ( 1.0 * $out_traffic * 100 ) / $iface_speed );

my $in_prefix  = "k";
my $out_prefix = "k";

if ( $in_traffic > 1024 ) {
	$in_traffic = sprintf( "%.2f", $in_traffic / 1024 );
	$in_prefix = "M";
}

if ( $out_traffic > 1024 ) {
	$out_traffic = sprintf( "%.2f", $out_traffic / 1024 );
	$out_prefix = "M";
}

$in_bytes  = sprintf( "%.2f", $in_bytes / 1024 );
$out_bytes = sprintf( "%.2f", $out_bytes / 1024 );

my $exit_status = "OK";

my $output = "Total RX Bytes: $in_bytes MB, Total TX Bytes: $out_bytes MB<br>";
$output .=
    "Average Traffic: $in_traffic "
  . $in_prefix . "B/s ("
  . $in_usage
  . "%) in, $out_traffic "
  . $out_prefix . "B/s ("
  . $out_usage
  . "%) out";

if ( ( $in_usage > $crit_usage ) or ( $out_usage > $crit_usage ) ) {
	$exit_status = "CRITICAL";
}

if (   ( $in_usage > $warn_usage )
	or ( $out_usage > $warn_usage ) && $exit_status eq "OK" )
{
	$exit_status = "WARNING";
}

$output .= "<br>$exit_status bandwidth utilization.\n"
  if ( $exit_status ne "OK" );

$output .=
"| inUsage=$in_usage,$warn_usage,$crit_usage outUsage=$out_usage,$warn_usage,$crit_usage "
  . "inAbsolut=$in_traffic_absolut outAbsolut=$out_traffic_absolut\n";

print $output;
exit( $STATUS_CODE{$exit_status} );

sub fetch_ifdescr {
	my $state;
	my $response;

	my $snmpkey;
	my $answer;
	my $key;

	my ( $session, $ifdescr ) = @_;

	if ( !defined( $response = $session->get_table($snmpIfDescr) ) ) {
		$answer = $session->error;
		$session->close;
		$state = 'CRITICAL';
		$session->close;
		exit $STATUS_CODE{$state};
	}

	foreach $key ( keys %{$response} ) {
		if ( $response->{$key} =~ /^$ifdescr$/ ) {
			$key =~ /.*\.(\d+)$/;
			$snmpkey = $1;

			# print "$ifdescr = $key / $snmpkey \n";  #debug
		}
	}
	unless ( defined $snmpkey ) {
		$session->close;
		$state = 'CRITICAL';
		printf "$state: Could not match $ifdescr \n";
		exit $STATUS_CODE{$state};
	}
	return $snmpkey;
}

#added 20050416 by mw
#Converts an input value to value in bits
sub bits2bytes {
	return unit2bytes(@_) / 8;
}

#added 20050416 by mw
#Converts an input value to value in bytes
sub unit2bytes {
	my ( $value, $unit ) = @_;

	if ( $unit eq "g" ) {
		return $value * 1024 * 1024 * 1024;
	}
	elsif ( $unit eq "m" ) {
		return $value * 1024 * 1024;
	}
	elsif ( $unit eq "k" ) {
		return $value * 1024;
	}
	else {
		print "You have to supplie a supported unit\n";
		exit $STATUS_CODE{'UNKNOWN'};
	}
}

#added 20050414 by mw
#This function detects if an overflow occurs. If so, it returns
#a computed value for $bytes.
#If there is no counter overflow it simply returns the origin value of $bytes.
sub counter_overflow {
	my ( $bytes, $last_bytes, $max_bytes ) = @_;

	$bytes += $max_bytes if ( $bytes < $last_bytes );
	$bytes = 0 if ( $bytes < $last_bytes );
	return $bytes;
}

#cosmetic changes 20050614 by mw
#Couldn't sustaine "HERE";-), either.
sub print_usage {
	print <<EOU;
    Usage: check_iftraffic.pl -H host -i if_descr -b if_max_speed [ -w warn ] [ -c crit ]


    Options:

    -H --host STRING or IPADDRESS
        Check interface on the indicated host.
    -C --community STRING 
        SNMP Community.
    -i --interface STRING
        Interface Name
    -b --bandwidth INTEGER
        Interface maximum speed in kilo/mega/giga/bits per second.
    -u --units STRING
        gigabits/s,m=megabits/s,k=kilobits/s,b=bits/s.
    -w --warning INTEGER
        % of bandwidth usage necessary to result in warning status (default: 85%)
    -c --critical INTEGER
        % of bandwidth usage necessary to result in critical status (default: 98%)
    -M --max INTEGER
	Max Counter Value of net devices in kilo/mega/giga/bytes.

EOU

	exit( $STATUS_CODE{"UNKNOWN"} );
}

