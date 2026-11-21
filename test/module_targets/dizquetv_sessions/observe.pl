use strict;
use warnings;
use IO::Socket::INET;
use Socket qw(inet_ntoa);

my $mode = shift // '';
if ($mode eq 'callback') {
    my ($token, $port) = @ARGV;
    die 'Invalid callback arguments' unless $token =~ /\Adizquetv-[a-zA-Z0-9]+\z/ && $port =~ /\A[0-9]+\z/;
    alarm 15;
    my $host = inet_ntoa(scalar gethostbyname('host.docker.internal'));
    my $socket = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'tcp', Timeout => 5) or die "Callback failed: $!";
    $socket->autoflush(1);
    my $identity = join("\t", $token, $<, $$, getppid(), $host) . "\n";
    print {$socket} $identity;
    my $reply = <$socket> // '';
    die 'Incorrect acknowledgment' unless $reply eq "ACK:$token\n";
    close $socket;
    print $identity;
} elsif ($mode eq 'state') {
    # Transport procfs bytes without optional JSON/MIME packages. The host
    # parses the documented fields: https://docs.kernel.org/filesystems/proc.html
    for my $directory (sort { substr($a, 6) <=> substr($b, 6) } glob('/proc/[0-9]*')) {
        next if $directory eq "/proc/$$";
        my @values;
        for my $name ('stat', 'cmdline', 'status') {
            if (open my $handle, '<:raw', "$directory/$name") {
                local $/; push @values, <$handle>; close $handle;
            } elsif (!-d $directory) { last; }
            else { die "Cannot read $directory/$name: $!"; }
        }
        next unless @values == 3;
        my @inodes;
        for my $descriptor (glob("$directory/fd/*")) {
            my $link = readlink($descriptor) // '';
            push @inodes, $1 if $link =~ /\Asocket:\[([0-9]+)\]\z/;
        }
        print join("\t", 'process', substr($directory, 6), (map { unpack('H*', $_) } @values), join(',', sort {$a <=> $b} @inodes)), "\n";
    }
    for my $name ('tcp', 'tcp6') {
        open my $handle, '<:raw', "/proc/net/$name" or die "Cannot read /proc/net/$name: $!";
        local $/; my $bytes = <$handle>; close $handle;
        print join("\t", 'network', $name, unpack('H*', $bytes)), "\n";
    }
} else { die 'Unknown observation mode'; }
