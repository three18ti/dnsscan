#!/usr/bin/perl
 
use warnings;
use strict;
 
use Net::IP;
use Net::DNS;
use IO::Select;
use Getopt::Long;
use Pod::Usage;
 
my $verbose = 0;
my $help = 0;
my $man = 0;
my $at_once = 100;
my $retries = 2;
my $timeout = 1;
my $fqdn = 'www.xyzzy.net';
 
GetOptions(
'verbose|v' => \$verbose,
'help|h|?' => \$help,
'man' => \$man,
'queries|q=i' => \$at_once,
'retries|r=i' => \$retries,
'timeout|t=i' => \$timeout,
'fqdn|f=s' => \$fqdn,
) or pod2usage(2);
 
pod2usage(1) if ($help);
pod2usage(-exitstatus => 0, -verbose => 2) if ($man);
 
my %state;
 
my $range = $ARGV[0];
 
if (not defined $range) {
print STDERR "Expected IP range as first argument\n";
pod2usage(2);
}
 
if (! sanity_check($fqdn)) {
print STDERR "Can't seem to resolve '$fqdn' from here." .
" Does it still exist and is the local nameserver working? Pick" .
" another FQDN with --fqdn if you need to.\n";
exit 1;
}
 
my $ip = new Net::IP($range);
 
if (not defined $ip) {
print STDERR "That ($range) doesn't look like a valid IP range\n";
pod2usage(2);
}
 
my $sel = IO::Select->new;
 
my $queried = 0;
my $start = time();
 
logger("Launching queries against " . $ip->print . ", $at_once at a time...");
 
$ip = launch_queries($ip, $sel, $at_once);
 
if ($verbose) {
logger("Got " . $sel->count . " queries in flight...");
}
 
my @ready;
 
# All the sockets we're waiting on are kept in %state.
while (keys %state) {
@ready = $sel->can_read(2);
 
if (@ready) {
# There's some sockets ready to read.
foreach my $sock (@ready) {
handle_result($sock);
$queried++;
 
# Now it's been read, get rid of it.
$sel->remove($sock);
$sock = undef;
 
if ($verbose) {
logger((scalar keys %state) . " queries remain");
}
}
} else {
# There's nothing ready to read, so do a check to see if any of them
# have been waiting around for too long, in which case get rid of them.
my $now = time();
 
foreach my $sock ($sel->handles) {
if ($now - $state{$sock}{when} > ($timeout * 2)) {
my $their_ip = $state{$sock}{ip};
 
if ($verbose) {
logger("Query for $their_ip timed out");
}
 
$queried++;
 
$state{$sock}{dns} = undef;
 
$sel->remove($sock);
 
delete $state{$sock};
}
}
 
if ($verbose) {
logger("Timed out waiting for DNS results - "
. (scalar keys %state) . " queries remain");
}
}
 
# Launch some more queries if necessary.
$ip = launch_queries($ip, $sel, $at_once);
}
 
logger("$queried IPs queried in " . (time() - $start) . "s");
 
exit 0;
 
# Launch DNS queries.
#
# ip - Net::IP object to work on
# sel - IO::Select set to add sockets to when the query is launched
# at_once - How many queries to have in flight at once
sub launch_queries
{
my ($ip, $sel, $at_once) = @_;
 
while ($ip and ($sel->count < $at_once)) {
check_resolver($ip, $sel);
$ip++;
}
 
return $ip;
}
 
# Launch a query against a single IP address.
#
# ip - the Net::IP object to test against
# sel - the IO::Select set to add the socket to
sub check_resolver
{
my ($ip, $sel) = @_;
 
logger("Checking " . $ip->ip . "...") if ($verbose);
 
my $dns = new Net::DNS::Resolver;
 
# Use only this nameserver.
$dns->nameservers($ip->ip);
 
# Do recurse.
$dns->recurse(1);
 
# Ignore any search list.
$dns->dnsrch(0);
 
# Don't append anything to the end.
$dns->defnames(0);
 
# Allow 1 second retransmit.
$dns->retrans($timeout);
 
# Allow 2 retries.
$dns->retry($retries);
 
# Go.
my $sock = $dns->bgsend($fqdn, 'A');
 
# Record the IP address, Net::DNS::Resolver object and starting time
# against this socket.
$state{$sock}{ip} = $ip->ip;
$state{$sock}{dns} = $dns;
$state{$sock}{when} = time();
 
$sel->add($sock);
}
 
# Read a DNS response from a socket that is ready.
#
# sock - the socket to read.
sub handle_result
{
my ($sock) = @_;
 
if (not exists $state{$sock}) {
die "Socket $sock somehow is not present in our state hash";
}
 
# Look up the IP address and Net::DNS::Resolver object corresponding to
# this socket.
my $ip = $state{$sock}{ip};
my $dns = $state{$sock}{dns};
 
my $packet = $dns->bgread($sock);
 
# If there's an immediate failure then the packet will be undef. The packet
# might also be empty. Both of those are okay, but if there i any sort of
# response other than that then it's probably an open resolver.
if (defined $packet and $packet->answer) {
print "!!! Got answer from $ip - possible open resolver!\n";
$packet->print if ($verbose);
} else {
logger("No answer from $ip") if ($verbose);
}
 
# Delete from state now we're finished with this socket.
$state{$sock}{dns} = undef;
delete $state{$sock};
 
return $packet;
}
 
sub logger
{
my ($msg) = @_;
 
print STDERR "# ", scalar gmtime(), "| $msg\n";
}
 
# Check that the FQDN that we're going to query is actually visible on the
# Internet, otherwise this will be a waste of time.
sub sanity_check
{
my ($fqdn) = @_;
 
my $dns = Net::DNS::Resolver->new;
my $query = $dns->search($fqdn, 'A');
 
return $query;
}
 
__END__
 
=pod
 
=head1 NAME
 
find_open_resolvers.pl -- Finds open DNS resolvers inside a given IP range
 
=head1 SYNOPSIS
 
find_open_resolvers.pl [options] [IP range]
 
Options:
--queries simultaneous queries to perform (100)
--retries number of retries of DNS query (2)
--timeout timeout for DNS query in seconds (1)
--fqdn Fully Qualified Domain Name to query for (www.xyzzy.net)
--verbose be verbose
--help display brief help
--man display full man page
 
IP range Range of IPv4 or v6 addresses
 
=head1 OPTIONS
 
=over 4
 
=item B<IP range>
 
B<Required>. Range of IPv4 or IPv6 addresses to check for open resolvers. Will iterate through them one by one. Accepts:
 
=over 4
 
=item * A single address (192.168.0.1)
 
=item * A CIDR range (192.68.0.0/24)
 
=item * A range, enclosed in quotes, specifying start to finish ('192.168.0.4 - 192.168.1.2')
 
=back
 
=item B<-q>, B<--queries>
 
How many simultaneous DNS queries to be working on at any one time. Defaults to 100.
 
=item B<-r>, B<--retries>
 
Number of retries to perform for each DNS query in the event of no response. Defaults to 2.
 
=item B<-t>, B<--timeout>
 
How long in seconds to wait for a response from each DNS query. Defaults to 1.
 
=item B<-f>, B<--fqdn>
 
Fully Qualified Domain Name (i.e., a host name) to query for. Should be something that no IP address is likely to be an authoritative DNS server for. Defaults to 'www.xyzzy.net'.
 
=item B<-v>, B<--verbose>
 
Operate verbosely.
 
=item B<-h>, B<-?>, B<--help>
 
Display a brief help message.
 
=item B<--man>
 
Display documentation in manual page format.
 
=back
 
=head1 DESCRIPTION
 
Pings off a bunch of DNS queries against every IP address in the specified range in order to see if any of them are likely to be open DNS resolvers.
 
Every IP address in the range is tested in batches of (by default) 100 in a select loop. Testing large ranges may take a very long time.
 
By default this queries for the FQDN 'www.xyzzy.net' which is an arbitrary choice that is unlikely to be authoritatively served by any target IP. Should a target IP return actual results for this FQDN then it is likely to be an open recursive resolver. If 'www.xyzzy.net' no longer exists in the global DNS then you may wish to specify another FQDN.
 
=head1 AUTHOR
 
Andy Smith <andy@bitfolk.com>
 
=head1 COPYRIGHT AND LICENSE
 
Copyright © 2012-2013 Andy Smith <andy@bitfolk.com>.
 
This program is free software; you can redistribute it and/or modify it under
the terms of the Perl Artistic License.
 
=cut
