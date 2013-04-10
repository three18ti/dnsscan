package DNSScanner;
use 5.010;
use strict;
use warnings;

use Moose;

use Net::IP;
use Net::DNS;
use IO::Select;

# handle multiple open file handles
has 'select' => (
    is      => 'ro',
    isa     => 'IO::Select',
    default => sub { IO::Select->new },
);

# holds open filehandles/sockets for dns request
has 'state' => (
    is      => 'rw',
    isa     => 'HashRef',
    default => sub { {} },
);

# supposed to count running quries
has 'queried' => (
    is      => 'rw',
    isa     => 'Int',
    default => '0',
);

# start time
has 'start' => (
    is      => 'ro',
    isa     => 'Int',
    default => sub { time },
);

# how many ips to scan at once
has 'at_once' => (
    is      => 'ro',
    isa     => 'Int',
    default => '100',
);

# domain to use for testing recursion
has 'search_domain' => (
    is      => 'ro',
    isa     => 'Str',
    default => 'google.com',
);

# time inbetween requests
has 'timeout'   => (
    is      => 'ro',
    isa     => 'Int',
    default => '1',
);

# number of times to retry request
has 'retry'     => (
    is      => 'ro',
    isa     => 'Int',
    default => '2',
);

# Set verbose logging to STDERR
has 'verbose' => (
    is      => 'ro',
    isa     => 'Int',
    default => '0',
);

# positive responses
has 'hits' => (
    is      => 'rw',
    isa     => 'ArrayRef',
    default => sub { [] },
);

# main loop,
sub launch_scan {
    my $self = shift;
    my $range = shift;

    my $ip = Net::IP->new($range);

    $self->logger("Launching queries against " . $ip->print . ", in sets of " . $self->at_once . " at a time...") 
        if $self->verbose;

    my @ready;
    do {
        @ready = $self->select->can_read(2);

        if (@ready) {
            foreach my $socket (@ready) {
                $self->handle_result($socket);
                #$self->queried = $self->queried + 1;

                $self->select->remove($socket);

                #$self->logger(scalar keys %{$self->state} . " remaining") if $self->verbose;
            }
        }
        else {
            my $now = time;
            foreach my $socket ($self->select->handles) {
                if ($now - $self->state->{$socket}->{when} > $self->timeout * 2) {
                    my $resolver_ip = $self->state->{$socket}->{ip};

                    $self->logger("Query for $resolver_ip timed out") if $self->verbose;

                    #$self->queried++;

                    $self->state->{$socket} = undef;
                    delete $self->state->{$socket};

                    $self->select->remove($socket);
                }
            }
        }
        $ip = $self->launch_queries($ip);
        $self->logger($self->select->count . "queries running...") if $self->verbose;
    } while (keys $self->state);
}

# launch set num of queries
sub launch_queries {
    my $self = shift;
    my $ip = shift;

    while ($ip and ($self->select->count < $self->at_once)) {
        $self->check_resolver($ip);
        $ip++
    }
    return $ip;
}

# perform dns query
sub check_resolver {
    my $self = shift;
    my $resolver_ip = shift;

    $self->logger("Checking " . $resolver_ip->ip ) if $self->verbose;

    # create new DNS object
    my $dns = Net::DNS::Resolver->new;

    # set nameserver
    $dns->nameservers($resolver_ip->ip);

    # Ignore search list
    # don't append anything to the end of the result
    $dns->dnsrch(0);
    $dns->defnames(0);

    # allow timeout, default 1sec
    $dns->retrans($self->timeout);

    # allow retries, default 2
    $dns->retry($self->retry);

    my $socket = $dns->bgsend($self->search_domain, 'A', );

    $self->state->{$socket}->{ip}   = $resolver_ip->ip;
    $self->state->{$socket}->{dns}  = $dns;
    $self->state->{$socket}->{when} = time;

    $self->select->add($socket);
}

# pickup the socket and read the result
sub handle_result {
    my $self = shift;
    my $socket = shift;

    (warn "Socket $socket does not exist" && next) unless exists $self->state->{$socket};

    my $ip = $self->state->{$socket}->{ip};
    my $dns = $self->state->{$socket}->{dns};

    my $packet = $dns->bgread($socket);

    unless (defined $packet and $packet->answer) {
        $self->logger("No answer from $ip") if $self->verbose;
    }
    else {
        say "[*] Got answer from $ip - Possible open resolver" if $self->verbose;
        $packet->print if $self->verbose;
        push @{$self->hits}, $ip;
    }
    
    $self->state->{$socket} = undef;
    delete $self->state->{$socket};
}


sub logger {
    my $self = shift;
    my $message = shift;
    my $FH = shift || *STDERR;
    say $FH "# " . scalar gmtime() . "| $message";
}

# print a nice "formatted" report
sub print_report_nice {
    my $self = shift;
    my $FH = shift || *STDOUT;

    say $FH "[*] Got answer from $_ - Possible open resolver" foreach @{$self->hits};
}

# report only the ips that responded positively
sub print_hits {
    my $self = shift;
    my $FH = shift || *STDOUT;

    say $FH $_ foreach @{$self->hits};
    
}

# checks that the search domain is valid
sub valid_domain {
    my $self = shift;
    my $dns = Net::DNS::Resolver->new;
    my $query = $dns->search($self->search_domain, 'A');

    return $query;
}

1;
