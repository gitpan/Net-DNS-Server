package Net::DNS::Server;

require 5.005_62;
use Carp;
use Net::DNS;
use IO::Select;
use Net::DNS::Method;
use NetAddr::IP 3.00;
use IO::Socket::INET;

use strict;
use warnings;

our $VERSION = '1.46';

sub new {
    my $type = shift;
    my $class = ref($type) || $type || "Net::DNS::Server";

    my $port = shift or croak "Must provide a port to bind the server";
    my $r_methods = shift;

    croak "Must provide a reference to a list of objects"
	unless ref($r_methods) eq "ARRAY";

    my $usocket = new IO::Socket::INET('LocalAddr' => $port,
				       'Proto' => 'UDP',
				       )
	or return;

    my $tsocket = new IO::Socket::INET('LocalAddr' => $port,
				       'Proto' => 'TCP',
				       'Listen' => SOMAXCONN,
				       'Reuse' => 1,
				       )
	or return;

    my $sel = new IO::Select;
    $sel->add($usocket);
    $sel->add($tsocket);

    my $self = {
	q => undef,
	qp => undef,
	ans => undef,
	port => $port,
	socket => undef,
	tsocket => $tsocket,
	usocket => $usocket,
	r_methods => $r_methods,
	action => NS_FAIL | NS_IGNORE,
	sel => $sel,
	pq => [],
    };

    bless $self, $class;
}

sub _build_default_ans {
    my $self = shift;

    $self->{ans} = new Net::DNS::Packet($self->{q}->qname,
					$self->{q}->qtype,
					$self->{q}->qclass);

    $self->{ans}->header->rcode('SERVFAIL');
    $self->{ans}->header->aa(1); # Authoritative
    $self->{ans}->header->qr(1); # Recursion provided 
    $self->{ans}->header->ra(1); # Recursion available

				# Recursion desired
    $self->{ans}->header->rd($self->{qp}->header->rd()); 
    $self->{ans}->header->id($self->{qp}->header->id());
}

sub get_question {
    my $self = shift;
    my $tout = shift;
    my $data;
    my @s;
    
    $self->{action} = NS_FAIL | NS_IGNORE;


    if (!@{$self->{pq}}) {	# If not pending questions...

	@s = $self->{sel}->can_read($tout);
	return unless @s;

	foreach my $socket (@s) {	# Queue questions

	    my $ns;

	    if ($socket eq $self->{usocket}) {
		$socket->recv($data, &Net::DNS::PACKETSZ)
		    or next;
		$ns = $socket;
	    }
	    elsif ($socket eq $self->{tsocket}) {
		$ns = $socket->accept;
		next unless $ns;
		$ns->read($data, 2);
		my $length = unpack("n", $data);
		$ns->read($data, $length);
		next unless length($data);
	    }
	    else {
		$ns = $socket;
		if ($ns->read($data, 2)) {
		    my $length = unpack("n", $data);
		    $ns->read($data, $length);
		    next unless length($data);
		}
		else {
		    $self->{sel}->remove($socket);
		    next;
		}
	    }

	    my $q = new Net::DNS::Packet (\$data)
		or next;

	    push @{$self->{pq}}, [ $ns, $q ];
	}

    }

    return @{$self->{pq}};
}

sub process {
    my $self = shift;
    my $uarg = shift;

    my $rq = shift @{$self->{pq}};

    return unless $rq;
    
    $self->{socket} = $rq->[0];
    $self->{qp} = $rq->[1];

    my $to = new NetAddr::IP($self->{socket}->sockhost());
    my $to_port = $self->{socket}->sockport();
    my $from = new NetAddr::IP($self->{socket}->peerhost());
    my $from_port = $self->{socket}->peerport();

    foreach my $q ($self->{qp}->question) {

	$self->{q} = $q;

	$self->_build_default_ans();

	my $qtype = uc $self->{q}->qtype;

	if ($qtype eq 'AXFR'
	    and defined $self->{socket}->socktype
	    and $self->{socket}->socktype == SOCK_DGRAM) 
	{
	    $self->{action} = NS_FAIL | NS_STOP;
	    last;
	}

	foreach my $m (@{$self->{r_methods}}) {
	    $self->{action} = $m->$qtype($self->{q}, 
					 $self->{ans},
					 {
					     'from' => $from,
					     'to' => $to,
					     'from_port' => $from_port,
					     'to_port' => $to_port,
					     'query' => $self->{qp},
					     'user' => $uarg,
					 });
	    last if ($self->{action} & NS_STOP);
	}
    }

    return 1;
}

sub send_response {
    my $self = shift;
    
    return if not defined $self->{socket};

    my $socket = $self->{socket};
    $self->{socket} = undef;

    if (not $self->{action} & NS_IGNORE) {

	my $ans;

	if ($self->{action} & NS_SPLIT
	    and $ans = Net::DNS::Packet->new($self->{ans})
	    and length($ans->data) > 65000)
	{
	    $ans = undef;

	    my $bytes = 0;

	    if (not (defined $socket->socktype
		     and $socket->socktype == SOCK_DGRAM))
	    {
		if ($self->{q}->qtype eq 'AXFR') {
		    $self->{sel}->remove($socket);
		}
		else {
		    $self->{sel}->add($socket);
		}
	    }

	    foreach my $ans ($self->{ans}->answer) {

		my $frag = new Net::DNS::Packet($ans->name, 
						$ans->type, 
						$ans->class);

		$frag->header->id($self->{ans}->header->id());
		$frag->header->rcode($self->{ans}->header->rcode());
		$frag->push('answer', $ans);
	    
		my $data = $frag->data;

		if (not (defined $socket->socktype
			 and $socket->socktype == SOCK_DGRAM))
		{
		    eval { $socket->send(pack("n", length($data))); };
		    return if $@;
		}
		
		$bytes += $socket->send($data);

	    }

	    return $bytes;
	}
	else {
	    $ans = undef;
	    my $data = $self->{ans}->data;

	    if (not (defined $socket->socktype
		     and $socket->socktype == SOCK_DGRAM))
	    {
		if ($self->{q}->qtype eq 'AXFR') {
		    $self->{sel}->remove($socket);
		}
		else {
		    $self->{sel}->add($socket);
		}
		eval { $socket->send(pack("n", length($data))); };
		return if $@;
	    }

	    eval { $socket->send($data); };
	    return if $@;
	    return 1;
	}
    }
    else {
	return;
    }
}

sub q {
    return $_[0]->{'q'};
}

sub answer {
    return $_[0]->{'ans'};
}

1;
__END__
=head1 NAME

Net::DNS::Server - Perl extension to implement dynamic DNS servers

=head1 SYNOPSIS

  use Net::DNS::Server;

  my $s = new Net::DNS::Server ($addr, \@methods);

  while (my $n = $s->get_question($timeout)) {
				# Some code
      foreach (0..$n) {
	  $s->process($private_data);
	  $s->send_response();
	  $question = $s->q();
	  $answer = $s->answer();
      }
				# Some more code
  }

  OR

  while ($s->get_question($timeout)) {
				# Some code
      while ($s->process()) {
	  $s->send_response();
	  $question = $s->q();
	  $answer = $s->answer();
      }
				# Some more code
  }


=head1 DESCRIPTION

This module implements the basis for a simple, event-loop-based DNS
server. In general, the code of a DNS server looks like what is presented
in the synopsis earlier in this document.

Once a DNS question is received, this module's C<-E<gt>get_question()>
method will invoke the methods provided in order to generate a
suitable answer. After this process is completed it will return a true
value so that the user-provided event loop can take control. If the
optional timeout expires before a question is received, this method
will return a false value.

The methods passed to C<-E<gt>get_question()> in the list reference
are objects of classes derived from Net::DNS::Method. These objects
must provide a method for each type of question (A, PTR, ...). The
inheritance mechanism makes this easy as Net::DNS::Method already
provides methods for all the RRs known to Net::DNS.

Those methods are invoked passing the current DNS question, the
potential answer packet and a reference to a hash containing various
pieces of information. The methods should check the question to see if
they apply to it (if it matches) and if this is the case, modify the
answer packet accordingly. After this actions are performed, they can
C<return()> with the OR of the various NS_* constants in order to tell
C<-E<gt>get_question()> what to do next.

The passed hash contains a number of entries that are discussed below:

=over

=item E<gt>{from}

A NetAddr::IP object containing the address of the host that sent the
request in the first place.

=item E<gt>{from_port}

From which port was the request sent.

=item E<gt>{to}

A NetAddr::IP object containing the address to which the request was
sent.

=item E<gt>{to_port}

To which port was the request sent.

=item E<gt>{user}

The scalar passed to E<gt>process(). This can be used to supply
additional information to the methods, such as a dynamic set of
filters.

=back

The following methods are provided by Net::DNS::Server:

=over

=item C<-E<gt>new($addr, $r_methods)>

Creates a server that will listen at UDP address/port C<$addr> and
uses methods in the list referenced by $r_methods. Returns a
Net::DNS::Server object if everything goes well or undef in case of
errors. These might include the inability to create a socket.

=item C<-E<gt>get_question($timeout)>

Waits for up to C<$timeout> seconds for a question to arrive.  If
C<$timeout> is undefined or zero, the call will block until a question
is received. If C<$timeout> expires before getting any questions or
any error condition is detected, the call will return a false value.

=item C<-E<gt>process($data)>

Calculates a response for the next pending question. Returns true if
there are questions pending to process. The optional parameter
C<$data> is passed to the methods in the hash they receive as the
third parameter.

=item C<-E<gt>send_response()>

Sends the previously calculated response to the client.

=item C<-E<gt>q()>

Returns the last question received.

=item C<-E<gt>answer()>

Returns the last answer received.

=back

=head2 EXPORT

None by default.

=head1 AUTHOR

Luis E. Muñoz <luismunoz@cpan.org>

=head1 CAVEATS

Normally the DNS servers use port 53. Your script must have root
privileges in order to bind to this port.

=head1 SEE ALSO

perl(1), Net::DNS(3), Net::DNS::Method(3), NetAddr::IP(3)

=cut

