use strict;
use warnings;
use JSON::PP;

my $port = shift @ARGV;
die "Invalid controlled port" unless defined($port) && $port =~ /^\d+$/ && $port > 0 && $port < 65536;
my @connections;
for my $table ('/proc/net/tcp', '/proc/net/tcp6') {
    open my $handle, '<', $table or die "Cannot read $table: $!";
    <$handle>;
    while (my $line = <$handle>) {
        my @fields = split ' ', $line;
        next unless @fields > 9;
        my ($address, $remote_port) = split ':', $fields[2];
        next unless hex($remote_port) == $port;
        push @connections, { table => $table, local => $fields[1], remote => $fields[2], state => $fields[3], inode => $fields[9] };
    }
    close $handle;
}
my %inodes = map { $_->{inode} => 1 } @connections;
my @processes;
for my $directory (glob '/proc/[0-9]*') {
    my ($pid) = $directory =~ m{/proc/(\d+)$};
    next if $pid == $$;
    open my $status_handle, '<', "$directory/status" or next;
    local $/;
    my $status = <$status_handle>;
    close $status_handle;
    my ($uid) = $status =~ /^Uid:\s+(\d+)/m;
    next unless defined $uid;
    open my $stat_handle, '<', "$directory/stat" or next;
    my $stat = <$stat_handle>;
    close $stat_handle;
    my ($name, $tail) = $stat =~ /^\d+ \((.*)\) (.*)$/s;
    next unless defined $tail;
    my @fields = split ' ', $tail;
    next unless @fields > 19;
    open my $cmd_handle, '<', "$directory/cmdline" or next;
    my $cmdline = <$cmd_handle> // '';
    close $cmd_handle;
    $cmdline =~ s/\0/ /g;
    my @sockets;
    for my $descriptor (glob "$directory/fd/*") {
        my $link = readlink $descriptor;
        next unless defined $link && $link =~ /^socket:\[(\d+)\]$/;
        push @sockets, $1 if $inodes{$1};
    }
    push @processes, { pid => 0 + $pid, ppid => 0 + $fields[1], starttime => $fields[19], state => $fields[0],
                      uid => 0 + $uid, exe => (readlink "$directory/exe"), name => $name, cmdline => $cmdline, connection_inodes => \@sockets };
}
print JSON::PP->new->utf8->canonical->encode({ connections => \@connections, processes => \@processes });
