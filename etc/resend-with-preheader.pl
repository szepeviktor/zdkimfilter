#! /usr/bin/perl
#
# run `perldoc resend-with-preheader.pl`
# to read the "plain old documentation" below
#

=pod

=head1 NAME

resend-with-preheader.pl - resend a saved virus file

=head1 SYNOPSIS

B<resend-with-preheader.pl> [opt] I<file-with-preheader> I<[...]>

B<resend-with-preheader.pl> [opt] E<lt> I<file-with-preheader>

=head1 OPTIONS

=over

=item I<-a opt>

additional option I<opt> for sendmail

=item I<-s>

silent

=back

=head1 DESCRIPTION

A I<file with preheader> is a mail file with sender and recipients
prepended before the mail header.  The sender on the very first line,
followed by recipients one per line make up what is being called a
preheader.  An empty line separates the preheader from the header.

Mail messages with viruses are saved in that format by B<avfilter>.
This Perl script expects such format.  It reads sender and recipients,
and then runs C<sendmail -f sender recipients E<lt> rest-of-file>.

=head1 AUTHOR

Alessandro Vesely E<lt>vesely@tana.itE<gt>

=head1 SEE ALSO

B<sendmail>(1)
B<avfilter>(8)

=cut

use strict;
use warnings;
use Getopt::Std;

our($opt_a, $opt_s);
die unless getopts('a:s');

while (<>)
{
	last if sendit($_, $ARGV, \*ARGV);
}

sub sendit
{
	my $runprog = 'sendmail';
	my ($sender, $file, $fh) = @_;
	return 1 unless defined($sender);
	chomp($sender);
	my @sargs;

	while (<$fh>)
	{
		last if /^$/;
		chomp;
		push @sargs, $_;
	}

	unshift(@sargs, split(/ +/, $opt_a)) if ($opt_a);
	unshift(@sargs, $runprog, '-f', $sender);

	# system(@sargs) won't work if $runprog is setsuid
	my $command = join(' ', map
		/^$/? '"'. $_ .'"': $_, @sargs);
	unless ($opt_s)
	{
		print 'file: ', $file, "\n";
		print 'command and args: ', $command, "\n";
	}

	my $rtc;
	if ($file ne '-')
	{
		open(my $oldin, "<&STDIN"); # save stdin
		open(STDIN, "<&", $fh);  # dup current input
		$rtc = system('/bin/sh', '-c', $command);
		close(STDIN);
		open(STDIN, "<&", $oldin);
	}
	else
	{
		$rtc = system('/bin/sh', '-c', $command);
	}

	if ($rtc == -1) {
		print "failed to execute $runprog: $!\n";
	}
	elsif ($rtc & 127) {
		printf "$runprog died with signal %d, %s coredump\n",
			($rtc & 127),  ($rtc & 128) ? 'with' : 'without';
	}
	elsif (!defined($opt_s)) {
		$rtc <<= 8;

		print "$runprog exited with value $rtc\n";
	}

	return $rtc;
}
