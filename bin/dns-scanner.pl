#!/usr/bin/perl

use strict;
use warnings;
use 5.010;

use Net::IP;
use Getopt::Long::Descriptive;

use lib 'lib';
use DNSScanner;

my $range = $ARGV[0];

my $scanner = DNSScanner->new({ verbose => 1 });

my $ip = new Net::IP($range);
$scanner->logger("Launching queries against " . $ip->print . ", in sets of " . $scanner->at_once . " at a time...") 
    if $scanner->verbose;

$scanner->logger($scanner->select->count . "queries running...") if $scanner->verbose;

my @ready;
do {
    @ready = $scanner->select->can_read(2);
    
    if (@ready) {
        foreach my $socket (@ready) {
            $scanner->handle_result($socket);
#            $scanner->queried = $scanner->queried + 1;

            $scanner->select->remove($socket);

#            $scanner->logger(scalar keys %{$scanner->state} . " remaining") if $scanner->verbose;
        }
    }
    else {
        my $now = time;

        foreach my $socket ($scanner->select->handles) {
            if ($now - $scanner->state->{$socket}->{when} > $scanner->timeout * 2) {
                my $resolver_ip = $scanner->state->{$socket}->{ip};

                $scanner->logger("Query for $resolver_ip timed out") if $scanner->verbose;

#                $scanner->queried++;

                $scanner->state->{$socket} = undef;
                delete $scanner->state->{$socket};

                $scanner->select->remove($socket);
                
            }
        }
    }
    $ip = $scanner->launch_queries($ip);
}  while (keys $scanner->state);

$scanner->print_report_nice;
$scanner->print_hits;
