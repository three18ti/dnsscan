#!/usr/bin/perl

use strict;
use warnings;
use 5.010;

use Getopt::Long::Descriptive;

use lib 'lib';
use DNSScanner;

my $range = $ARGV[0];

my $scanner = DNSScanner->new({ verbose => 1 });

$scanner->logger($scanner->select->count . "queries running...") if $scanner->verbose;

#do the work
$scanner->launch_scan($range);

#reporting
$scanner->print_report_nice;
$scanner->print_hits;
