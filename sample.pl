package Net::DNS::Method::Sample;
use Net::DNS::Method;
use Net::DNS;

our @ISA = qw(Net::DNS::Method);

sub new { bless [], $_[0]; }

sub A { 
    my $self = shift;
    my $q = shift;
    my $a = shift;
    
    print "*** Invoked 'A' ! ***\n";

    $a->header->rcode('NOERROR');
    $a->push('answer', new Net::DNS::RR $q->qname . ' 10 IN A 127.0.0.1');
    return NS_OK;
}

package main;

use Net::DNS;
use Net::DNS::Method;
use Net::DNS::Server;

my $method = Net::DNS::Method::Sample->new;

my $server = new Net::DNS::Server ('127.0.0.1:53', [ $method ])
    or die "Cannot create server object: $!";

if ($server->get_question()) {
    print " get_question succesful\n";
    if ($server->send_response()) {
	print "send_response ok\n";
    }
    else {
	print "send_response failed: $!\n";
    }
}
else {
    print "get_question failed\n";
}

