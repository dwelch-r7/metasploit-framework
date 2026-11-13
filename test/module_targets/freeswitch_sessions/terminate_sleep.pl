use strict;
use warnings;
use Errno qw(ENOENT ESRCH);
use JSON::PP;

my ($pid, $birth, $uid) = @ARGV;
die "Invalid controlled process identity" unless defined($pid) && defined($birth) && defined($uid) && $pid =~ /\A[0-9]+\z/ && $pid > 1 && $birth =~ /\A[0-9]+\z/ && $uid =~ /\A[0-9]+\z/;
my $stat_handle;
if (!open($stat_handle, '<', "/proc/$pid/stat")) {
    die "Cannot inspect controlled process: $!" unless $! == ENOENT || $! == ESRCH;
    print JSON::PP->new->encode({ pid => 0 + $pid, status => 'already_absent' });
    exit;
}
my $stat = do { local $/; <$stat_handle> };
close $stat_handle;
my ($name, $tail) = $stat =~ /^\d+ \((.*)\) (.*)$/s;
my @fields = split ' ', $tail;
die "Controlled process identity changed" unless defined($name) && $name eq 'sleep' && $fields[19] eq $birth;
open my $status_handle, '<', "/proc/$pid/status" or die "Cannot read process status: $!";
my $status = do { local $/; <$status_handle> };
close $status_handle;
my ($actual_uid) = $status =~ /^Uid:\s+(\d+)/m;
die "Controlled process UID changed" unless defined($actual_uid) && $actual_uid == $uid;
open my $cmd_handle, '<', "/proc/$pid/cmdline" or die "Cannot read process command: $!";
my $command = do { local $/; <$cmd_handle> };
close $cmd_handle;
$command =~ s/\0/ /g;
die "Controlled process is not the observed sleep feeder" unless $command =~ /^sleep \d+\s*$/;
my $sent = kill 'TERM', $pid;
die "Cannot signal controlled sleep: $!" unless $sent || $! == ESRCH;
print JSON::PP->new->encode({ pid => 0 + $pid, starttime => $birth, uid => 0 + $uid, command => $command, status => $sent ? 'signalled' : 'already_absent' });
