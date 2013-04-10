#!/usr/bin/perl

use strict;
use warnings;
use 5.010;

use Getopt::Long::Descriptive;

use lib 'lib';
use DNSScanner;

my ($opt, $usage) = describe_options(
    "dns-scanner.pl %o ip-range/mask\ndns-scanner.pl %o 192.168.0.1/24",
    [ 'search-domain|s=s',  "The domain to use for testing",            { default => 'google.com', }, ],
    [ 'queries|q=i',        "How many queries to launch at once",       { default => '100', }, ],
    [ 'timeout|t=i',        "The time to wait for a DNS response",      { default => '1', }, ],
    [ 'retries|r=i',        "How many times to retry the request",      { default => '2', }, ],
    [],
#    [ 'nice-report',        "Print a formatted report", ],
    [ 'ips-only',           "Only print matching ips",  ],
    [],
    [ 'verbose|v',          "Show logging messages during execution",   { default => '0', }, ],
    [ 'help|h',             "Show this message and exit",   ],
);
say($usage->text), exit if $opt->help;

# create the scanner object
my $scanner = DNSScanner->new(
    {
        search_domain   => $opt->search_domain,
        queries         => $opt->queries,
        timeout         => $opt->timeout,
        retries         => $opt->retries,
        verbose         => $opt->verbose,
    },
);

say($usage->text . "\nInvalid Search Domain: " . $scanner->search_domain . "\n"), exit unless $scanner->valid_domain;

#do the work
foreach my $range (@ARGV) {
    # should actually validate that $range is an IP or IP range
    $scanner->launch_scan($range);
}

#reporting
$scanner->print_report_nice unless $opt->ips_only;
$scanner->print_hits if $opt->ips_only;
say "Total Time: " . (time - $scanner->start) . "s";
