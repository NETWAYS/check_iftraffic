# Icinga Check Plugin for Interface Traffic

Checks the utilization of a given interface name with SNMP.

Based on `check_traffic` from Adrian Wieczorek.

## Requirements

* Perl
* `Net::SNMP`

## License

This project is licensed under the terms of the GNU General Public License Version 2.

This software is Copyright (c) 2004 by NETWAYS GmbH [support@netways.de](mailto:support@netways.de).

## Support

For bugs and feature requests please head over to our [issue tracker](https://github.com/NETWAYS/check_iftraffic/issues).

## Installation

### RHEL/CentOS EPEL Repository

RHEL/CentOS requires the EPEL repository:

```
yum -y install epel-release
yum makecache
```

If you are using RHEL you need enable the `optional` repository and then install
the [EPEL rpm package](https://fedoraproject.org/wiki/EPEL#How_can_I_use_these_extra_packages.3F).

### Perl Dependencies

Debian/Ubuntu:

```
apt-get -y install libnet-snmp-perl
```

RHEL/CentOS/Fedora:

```
yum -y install perl-Net-SNMP
```

### Plugin Setup

Put this plugin into the Icinga PluginDir location.

Debian/Ubuntu:

```
install -o root -g root -m755 *.pl /usr/lib/nagios/plugins/
```

RHEL/CentOS/Fedora:

```
install -o root -g root -m755 *.pl /usr/lib64/nagios/plugins/
```

## Run

```
$ ./check_iftraffic.pl --help
    Usage: check_iftraffic.pl -H host -C community -V snmp_version -i if_descr
    -b if_max_speed -u unit [ -w warn ] [ -c crit ] [ -M max_counter_value ]

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
```

### Thresholds

Single thresholds or range based thresholds are supported according to the
Monitoring Plugins API specification.

### Examples

```
$ ./check_iftraffic.pl -H localhost -C public -i en0 -b 100 -u m
Total RX Bytes: 859.84 MB, Total TX Bytes: 1566.80 MB<br>Average Traffic: 0.00 kB/s (0.0%) in, 0.00 kB/s (0.0%) out| inUsage=0.0,85,98 outUsage=0.0,85,98 inAbsolut=880477 outAbsolut=1604405
```

## Configuration

The Icinga 2 CheckCommand is available inside the [ITL](https://icinga.com/docs/icinga2/latest/doc/10-icinga-template-library/#iftraffic).


## Contributing

Fork this repository on GitHub and send in a PR.

There's a `.perltidyrc` file in the main repository tree. If you are uncertain about the coding style,
create your patch and then run:

```
$ perltidy -b *.pl
```

This requires the `perltidy` module being installed.
