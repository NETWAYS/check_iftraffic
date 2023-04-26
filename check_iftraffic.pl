#!/usr/bin/perl -w
#
my $VERSION = "1.0.2";

# check_iftraffic.pl - Icinga network traffic monitor plugin
# Copyright (C) 2004 Gerd Mueller / Netways GmbH
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
my $iface_name;
my $iface_speed;
my $opt_h;
my $opt_version;
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
my $snmpIfName      = '1.3.6.1.2.1.31.1.1.1.1';

my $response;

# Path to  tmp files
my $TRAFFIC_FILE = "/tmp/traffic";

# Icinga specific
my %ERRORS = ('OK' => 0, 'WARNING' => 1, 'CRITICAL' => 2, 'UNKNOWN' => 3, 'DEPENDENT' => 4);

#default values;
my ($in_bytes, $out_bytes) = 0;
my $warn_usage = 85;
my $crit_usage = 98;
my $COMMUNITY  = "public";

my $max_value;
my $max_bytes;

my $status = GetOptions(
    "h|help"        => \$opt_h,
    "v"             => \$opt_version,
    "C|community=s" => \$COMMUNITY,
    "V|version=s"   => \$snmp_version,
    "w|warning=s"   => \$warn_usage,
    "c|critical=s"  => \$crit_usage,
    "b|bandwidth=i" => \$iface_speed,
    "p|port=i"      => \$port,
    "u|units=s"     => \$units,
    "i|interface=s" => \$iface_descr,
    "n|ifname=s"    => \$iface_name,
    "H|hostname=s"  => \$host_address,
    "M|max=i"       => \$max_value
);

if ($status == 0) {
    print_help();
    exit $ERRORS{'UNKNOWN'};
}
if (defined($opt_h))       { print_help();    exit $ERRORS{"UNKNOWN"} }
if (defined($opt_version)) { print_version(); exit $ERRORS{"UNKNOWN"} }

if ((!$host_address) or ((!$iface_descr) and (!$iface_name)) or (!$iface_speed)) {
    print_usage();
    exit $ERRORS{'UNKNOWN'};
}

$iface_speed = bits2bytes($iface_speed, $units) / 1024;
if (!$max_value) {
    #if no -M Parameter was set, set it to 32Bit Overflow
    $max_bytes = 419304;    # the value is (2^32/1024)
} else {
    $max_bytes = unit2bytes($max_value, $units);
}

if ($snmp_version =~ /[12]/) {
    ($session, $error) = Net::SNMP->session(
        -hostname  => $host_address,
        -community => $COMMUNITY,
        -port      => $port,
        -version   => $snmp_version
    );

    if (!defined($session)) {
        print("UNKNOWN: $error");
        exit $ERRORS{'UNKNOWN'};
    }
} elsif ($snmp_version =~ /3/) {
    my $state = 'UNKNOWN';
    print("$state: No support for SNMP v3 yet\n");
    exit $ERRORS{$state};
} else {
    my $state = 'UNKNOWN';
    print("$state: No support for SNMP v$snmp_version yet\n");
    exit $ERRORS{$state};
}

if ($iface_descr) {
	$iface_number = fetch_ifdescr($session, $iface_descr);
} else {
	$iface_number = fetch_ifname($session, $iface_name);
}

push(@snmpoids, $snmpIfInOctets . "." . $iface_number);
push(@snmpoids, $snmpIfOutOctets . "." . $iface_number);

if (!defined($response = $session->get_request(@snmpoids))) {
    my $answer = $session->error;
    $session->close;

    print("WARNING: SNMP error: $answer\n");
    exit $ERRORS{'WARNING'};
}

$in_bytes  = $response->{ $snmpIfInOctets . "." . $iface_number } / 1024;
$out_bytes = $response->{ $snmpIfOutOctets . "." . $iface_number } / 1024;

$session->close;

my $row;
my $last_check_time = time - 1;
my $last_in_bytes   = $in_bytes;
my $last_out_bytes  = $out_bytes;

if (open(FILE, "<" . $TRAFFIC_FILE . "_if" . $iface_number . "_" . $host_address)) {
    while ($row = <FILE>) {
        chomp($row);
        ($last_check_time, $last_in_bytes, $last_out_bytes) = split(":", $row);
    }
    close(FILE);
}

my $update_time = time;

open(FILE, ">" . $TRAFFIC_FILE . "_if" . $iface_number . "_" . $host_address)
    or die "Can't open $TRAFFIC_FILE for writing: $!";
printf FILE ("%s:%.0ld:%.0ld\n", $update_time, $in_bytes, $out_bytes);
close(FILE);

my $db_file;

#Check for and correct counter overflow (if possible).
#See function counter_overflow.
$in_bytes  = counter_overflow($in_bytes,  $last_in_bytes,  $max_bytes);
$out_bytes = counter_overflow($out_bytes, $last_out_bytes, $max_bytes);

my $in_traffic  = sprintf("%.2lf", ($in_bytes - $last_in_bytes) /   (time - $last_check_time));
my $out_traffic = sprintf("%.2lf", ($out_bytes - $last_out_bytes) / (time - $last_check_time));

my $in_traffic_absolut  = sprintf("%.0d", $last_in_bytes);
my $out_traffic_absolut = sprintf("%.0d", $last_out_bytes);

my $in_usage  = sprintf("%.1f", (1.0 * $in_traffic * 100) / $iface_speed);
my $out_usage = sprintf("%.1f", (1.0 * $out_traffic * 100) / $iface_speed);

my $in_prefix  = "k";
my $out_prefix = "k";

if ($in_traffic > 1024) {
    $in_traffic = sprintf("%.2f", $in_traffic / 1024);
    $in_prefix = "M";
}

if ($out_traffic > 1024) {
    $out_traffic = sprintf("%.2f", $out_traffic / 1024);
    $out_prefix = "M";
}

$in_bytes  = sprintf("%.2f", $in_bytes / 1024);
$out_bytes = sprintf("%.2f", $out_bytes / 1024);

my $exit_status = "OK";

my $output = "Total RX Bytes: $in_bytes MB, Total TX Bytes: $out_bytes MB<br>";
$output
    .= "Average Traffic: $in_traffic "
    . $in_prefix . "B/s ("
    . $in_usage
    . "%) in, $out_traffic "
    . $out_prefix . "B/s ("
    . $out_usage
    . "%) out";

if (($in_usage > $crit_usage) or ($out_usage > $crit_usage)) {
    $exit_status = "CRITICAL";
}

if ((($in_usage > $warn_usage) or ($out_usage > $warn_usage))
    && $exit_status eq "OK")
{
    $exit_status = "WARNING";
}

$output .= "<br>$exit_status bandwidth utilization.\n"
    if ($exit_status ne "OK");

$output .= "|inUsage=${in_usage}%;${warn_usage};${crit_usage} outUsage=${out_usage}%;${warn_usage};${crit_usage} "
    . "inAbsolut=${in_traffic_absolut}c outAbsolut=${out_traffic_absolut}c";

print $output;
exit($ERRORS{$exit_status});

sub fetch_ifdescr {
    my $state;
    my $response;

    my $snmpkey;
    my $answer;
    my $key;

    my ($session, $ifdescr) = @_;

    if (!defined($response = $session->get_table($snmpIfDescr))) {
        $answer = $session->error;
        $session->close;
        $state = 'CRITICAL';
        $session->close;
        printf "$state: Could not establish connection \n";
        exit $ERRORS{$state};
    }

    foreach $key (keys %{$response}) {
        if ($response->{$key} =~ /^$ifdescr$/) {
            $key =~ /.*\.(\d+)$/;
            $snmpkey = $1;
        }
    }
    unless (defined $snmpkey) {
        $session->close;
        $state = 'CRITICAL';
        printf "$state: Could not match IFDescr $ifdescr \n";
        exit $ERRORS{$state};
    }
    return $snmpkey;
}

sub fetch_ifname {
    my $state;
    my $response;

    my $snmpkey;
    my $answer;
    my $key;

    my ($session, $ifname) = @_;

    if (!defined($response = $session->get_table($snmpIfName))) {
        $answer = $session->error;
        $session->close;
        $state = 'CRITICAL';
        $session->close;
        printf "$state: Could not establish connection \n";
        exit $ERRORS{$state};
    }

    foreach $key (keys %{$response}) {
        if ($response->{$key} =~ /^$ifname$/) {
            $key =~ /.*\.(\d+)$/;
            $snmpkey = $1;
        }
    }
    unless (defined $snmpkey) {
        $session->close;
        $state = 'CRITICAL';
        printf "$state: Could not match IFName $ifname \n";
        exit $ERRORS{$state};
    }
    return $snmpkey;
}

#Converts an input value to value in bits
sub bits2bytes {
    return unit2bytes(@_) / 8;
}

#Converts an input value to value in bytes
sub unit2bytes {
    my ($value, $unit) = @_;

    if ($unit eq "g") {
        return $value * 1024 * 1024 * 1024;
    } elsif ($unit eq "m") {
        return $value * 1024 * 1024;
    } elsif ($unit eq "k") {
        return $value * 1024;
    } else {
        print "You have to supply a supported unit\n";
        exit $ERRORS{'UNKNOWN'};
    }
}

#This function detects if an overflow occurs. If so, it returns
#a computed value for $bytes.
#If there is no counter overflow it simply returns the origin value of $bytes.
sub counter_overflow {
    my ($bytes, $last_bytes, $max_bytes) = @_;

    $bytes += $max_bytes if ($bytes < $last_bytes);
    $bytes = 0 if ($bytes < $last_bytes);
    return $bytes;
}

sub print_version { print "$0 version: $VERSION\n"; }

sub print_usage {
    print
"Usage: $0 -H host -C community -V snmp_version ( -i if_descr | -n if_name ) -b if_max_speed -u unit [ -w warn ] [ -c crit ] [ -M max_counter_value ]\n";
}

sub print_help {
    print "SNMP Network Interface Plugin for Icinga/Nagios, Version ", $VERSION, "\n";
    print "GPLv2 license, (c) 2004 NETWAYS GmbH\n\n";
    print_usage();
    print <<EOT;
    Options:

    -H --host STRING or IPADDRESS
        Check interface on the indicated host.
    -C --community STRING
        SNMP Community.
    -V --version STRING
        SNMP version to use (default: 1)
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

     Example:

         check_iftraffic.pl -H localhost -C public -i en0 -b 100 -u m
EOT

    exit($ERRORS{"UNKNOWN"});
}
