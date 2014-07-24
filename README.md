iftraffic
=========

Checks the utilization of a given interface name with snmp. without the overhead of check_traffic.
   
Based on check\_traffic from Adrian Wieczorek

Usage 
-----
    check_iftraffic.pl -H host -i if_descr -b if_max_speed [ -w warn ] [ -c crit ]


Options
-------

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

  
   
   
   
