use strict;
use warnings;
use IO::Socket::INET;

alarm 3;
my $peer = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => 8000, Proto => 'tcp', Timeout => 2) or exit 1;
$peer->autoflush(1);
print $peer "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
my $line = <$peer>;
close $peer;
exit(!defined($line) || $line !~ m{\AHTTP/1\.[01] 200 });
