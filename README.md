sockstat(1) - list open sockets
===============================

List open sockets on Illumos with process information

This project originally started as https://github.com/bahamas10/illumos-sockets
but was rewritten to be faster and less invasive by not requiring any processes
to be stopped.

See [Issues](#issues) below for known issues, or lacking features

Examples
--------

Without any arguments, `sockstat` will show all udp and tcp sockets for both
ipv4 and ipv6 connections that exist on the system.

    $ ./sockstat
    USER      COMMAND         PID    PROTO  LOCAL ADDRESS          REMOTE ADDRESS
    riak      beam.smp        18637  udp4   127.0.0.1:4000         *.*
    root      rsyslogd        73903  udp4   127.0.0.1:514          *.*
    root      rsyslogd        73903  udp4   0.0.0.0:59763          *.*
    root      rsyslogd        73903  udp4   0.0.0.0:38105          *.*
    riak      epmd            18525  tcp4   0.0.0.0:4369           *.*
    riak      beam.smp        18637  tcp4   0.0.0.0:30589          *.*
    riak      beam.smp        18637  tcp4   127.0.0.1:16382        127.0.0.1:4369
    riak      epmd            18525  tcp4   127.0.0.1:4369         127.0.0.1:16382
    riak      beam.smp        18637  tcp4   10.0.0.1:8099          *.*
    riak      beam.smp        18637  tcp4   127.0.0.1:8098         *.*
    riak      beam.smp        18637  tcp4   10.0.0.1:8098          *.*
    riak      beam.smp        18637  tcp4   10.0.0.1:9080          *.*
    root      sshd            18901  tcp4   10.0.0.1:2222          *.*
    nagios    nrpe            18905  tcp4   10.0.0.1:5666          *.*
    root      sshd            18901  tcp4   10.0.0.1:2222          10.0.1.2:18082
    nobody    node            18250  tcp4   127.0.0.1:10501        *.*
    www       bud             41074  tcp4   0.0.0.0:443            *.*
    root      master          16086  tcp4   127.0.0.1:25           *.*
    voxer     redis-server    18362  tcp4   10.0.0.1:6411          *.*
    root      master          16086  tcp6   ::1:25                 *.*

Show ipv4 sockets only

    $ ./sockstat -4

Show ipv6 sockets that are listening

    $ ./sockstat -6 -l

Show any version tcp sockets that are connected

    $ ./sockstat -P tcp -c

Show listening sockets with process arguments

    $ ./sockstat -l -a

Prepend zonename in front of output

    $ ./sockstat -Z

See [Usage](#usage) below for more options

Usage
-----

Options inspiration from [sockstat(1)][4] on FreeBSD

    $ ./sockstat -h
    usage: sockstat [-46acHhLlz] [-P protcols] [-z zone]

    print sockets in use on the current system

    options
      -4             only show ipv4 sockets
      -6             only show ipv6 sockets
      -a             print process arguments
      -c             only show connected sockets
      -h             print this message and exit
      -H             don't print header
      -l             only show listening sockets
      -L             hide sockets that pertain to the loopback address (127.0.0.0/8 or ::1)
      -P <protos>    comma separated list of protocols, defaults to tcp,udp
      -z <zone>      only show sockets inside zone
      -Z             prefix lines with zone names

     - if neither '-4' or '-6' are supplied, both are assumed
     - if neither '-c' or '-l' are supplied, both are assumed

About
-----

`sockstat(1)` uses the same mechanism that `netstat(1)` uses (`/dev/arp`)
to list open sockets.

Performance
-----------

### `lsof`

Using `lsof` (which uses `pfiles(1)` under the hood) from the `smtools` package on:

A platform that does NOT include the https://www.illumos.org/issues/5397 patch

```
# ptime lsof -p >/dev/null

real     1:21.624016149
user        2.027642428
sys      1:19.689849204
```

A platform that does include the https://www.illumos.org/issues/5397 patch

```
# ptime lsof -p >/dev/null

real       11.418651896
user        2.204807567
sys         8.970867687
```

### `opensockets`

Using `opensockets` from https://github.com/bahamas10/illumos-sockets

```
# ptime ./opensockets >/dev/null

real        0.382610819
user        0.046179765
sys         0.241209266
```

### `sockstat`

Using this program (note that root is not needed!)

```
$ ptime ./sockstat > /dev/null

real        0.008942319
user        0.001051674
sys         0.006944528
```

### results

In the output above, the `real` time shows the actual time elapsed during
the programs execution.

- `lsof` - without patch - 1 minute 21 seconds
- `lsof` - with patch - 11.4 seconds
- `opensockets` - 0.38 seconds
- `sockstat` - 0.0089 seconds

First, just looking at `lsof`, the patch provides an incredible boost in speed
when running `pfiles(1)`, so `lsof` sees the benefits of it - it allows it to
return the same amount of information **13.5x** faster than before!

The good news is, this [patch has landed][2] in the [20150306T202346Z][3]
release of [SmartOS][1], so as time goes on it will become the new
normal for SmartOS and Illumos users.

However, when comparing this to `opensockets`, `opensockets` is **30x** faster
than even the fastest `lsof`!  Just for fun, that is **213x** faster than the
slowest `lsof`.

It's important to remember that the processes being interrogated by
`pfiles(1)` and `opensockets` are stopped as a result of this process.  So
speeding this task up has the added side-effect of reducing the problems
that can arise when running this on a production system with thousands
of open files/sockets.

`sockstat`, by contrast, does not freeze the processes during the interrogation
process, making it completely safe to run on production systems that could have
thousands of open sockets.

### round 2

When analyzing these results, because we are in the realm of milliseconds
it gets harder to compare directly as some of that time is a result
of process start up, resource allocation, etc.  To better compare these tools
we need to run them on a machine with more open sockets to increase the time it will
take.

The system for the following test has over 60k open files

```
# ls -U1 /proc/*/fd | wc -l
64868
```

Unfortunately, `lsof` can't be run on these machines as it will negatively affect
the services running, so this tool takes an instant fail on this one.  Pinning
`opensockets` against `sockstat` we see:

### `opensockets`

```
# ptime ./opensockets > /dev/null

real        63.79305093
user        1.066690544
sys         61.46024594
```

### `sockstat`

```
$ ptime ./sockstat > /dev/null

real        0.294612808
user        0.199964321
sys         0.092461649
```

### results

With 61,218 open sockets:

- `opensockets` - 1 minute 3 seconds
- `sockstat` - 0.29 seconds

It's clear that the procfs method breaks down the more files/sockets are open
on a machine, whereas `sockstat` barely takes longer than a quarter of a second.

---

Number of open sockets determined with

```
$ ./sockstat -H | wc -l
61218
```

Conclusion
----------

With the patch above for `libproc`, `pfiles(1M)` will be faster all around, and
this is almost always a good thing.  `pfiles(1M)` is an enormously helpful tool
for debugging both live and post-mortem issues... it is not being replaced by
`sockstat`.

`pfiles(1M)`, given a PID, can extract information for every open file the PID
has.  If all your interested in is socket information however, there can be a
lot of overhead from doing all of this work.  Instead, the proper approach is
to avoid interrogating the processes individually, and just ask the system
about its sockets, and then read process information from `/proc` - which is exactly
what `sockstat` does.

Issues
------

These are known issues with `sockstat` that *should* be fixed

- must compile with `-DNDEBUG`, otherwise assertions fail
- `-u` option - Unix domain socket support

License
-------

CDDL License

- `mib` - CDDL License - basically ripped straight from netstat.c on Illumos
- `sockstat` - CDDL License
- `proc_info` - CDDL License

[0]: http://illumos.org
[1]: http://smartos.org
[2]: https://github.com/illumos/illumos-gate/commit/d907f8b938aec9d8b57fdb15c241b98641b8b052
[3]: https://us-east.manta.joyent.com/Joyent_Dev/public/SmartOS/20150306T202346Z/index.html
[4]: http://www.freebsd.org/cgi/man.cgi?query=sockstat&sektion=1&n=1
