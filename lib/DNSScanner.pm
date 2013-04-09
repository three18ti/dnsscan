package DNSScanner;
use 5.010;
use strict;
use warnings;

use Moose;

use Net::IP;
use Net::DNS;
use IO::Select;

has 'select' => (
    is      => 'ro',
    isa     => 'IO::Select',
    default => sub { IO::Select->new },
);

has 'state' => (
    is      => 'rw',
    isa     => 'HashRef',
    default => sub { {} },
);

has 'queried' => (
    is      => 'rw',
    isa     => 'Int',
    default => '0',
);

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


sub launch_queries {
    my $self = shift;
    my $ip = shift;

    while ($ip and ($self->select->count < $self->at_once)) {
        $self->check_resolver($ip);
        $ip++
    }
    return $ip;
}

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
        say "[*] Got answer from $ip - Possible open resolver";
        $packet->print if $self->verbose;
    }
    
    $self->state->{$socket} = undef;
    delete $self->state->{$socket};
}


sub logger {
    my $self = shift;
    my $message = shift;
    say STDERR "# " . scalar gmtime() . "> $message";
}

sub sanity_check {
    my $self = shift;
    my $dns = Net::DNS::Resolver->new;
    my $query = $dns->search($self->search_domain, 'A');

    return $query ? '1' : '0';
}

1;
