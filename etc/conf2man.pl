#! /usr/bin/perl
use strict;
use warnings;
use Pod::Man;
use Data::Dumper;

my $version;
my $fname = "config.h";
$fname = "../$fname" if ! -f $fname;
open my $conf, "< $fname" or die "cannot read $fname: $!";
while (<$conf>)
{
	chomp;
	if (/^\s*\#define *PACKAGE_VERSION *\"(\S*)\"/)
	{
		#print $_,"\n";
		$version = $1;
		last;
	}
}
close $conf;
die "didn't find PACKAGE_VERSION" unless defined $version;

# global variables:
my @res = ();
my $line = '';

$fname = $ARGV[0];
defined($fname) or die 'must provide zdkimfilter.conf[.dist[.in]] as argument';
$fname = "etc/$fname" if ! -f $fname;
$fname = "../$fname" if ! -f $fname;

open $conf, "< $fname" or die "cannot read $fname: $!";
die "$fname is empty" unless <$conf>; # discard 1st line

my $basedir = '';
$basedir = $1 if $fname =~ /^(.*\/)[^\/]+$/;

my $fname_out = $basedir .'zdkimfilter.conf.5';
open my $man, "> $fname_out" or die "cannot write $fname_out: $!";

my $parser = Pod::Man->new(
	release => "zdkimfilter $version",
	center => 'zdkimfilter',
	section => 5,
	name => 'ZDKIMFILTER.CONF'
	);

$parser->output_fh($man);

$parser->parse_lines(("=pod\n", "\n"));
$parser->parse_lines(("=head2 NAME\n", "\n"));
$parser->parse_lines(("\n", "zdkimfilter.conf - zdkimfilter(8) configuration file\n", "\n"));
$parser->parse_lines(("=head2 SYNTAX\n", "\n"));

read_ahead(); # discard 2nd line
read_ahead();
read_para();
unshift @res, ("\n",
	'I<logic line> = [ C<#> I<comment> ] | I<name> [ C<=> ] [ I<value> ]'."\n",
	"\n",
	"The file consists of zero or more lines. \n");
pop @res; pop @res; # discard the bottom two lines of the intro.
$parser->parse_lines(@res);

$parser->parse_lines(("\n", "=head2 OPTIONS\n", "\n",
	"Valid names and their types are listed below.  All boolean values \n",
	"default to C<N>, while C<Y> is assumed if the name is specified but the \n",
	"value is omitted.  Most values default to NULL, but the program behaves \n",
	"differently.  For other cases, the default values are mentioned after \n",
	"the relevant description. \n",
	"\n"));

$parser->parse_lines(("=over\n", "\n"));

read_para();
while (scalar (@res > 1))
{
	$parser->parse_lines(@res);
	read_para();
}
$parser->parse_lines(("=back\n", "\n"));

#$parser->parse_lines("The configuration file consists of a sequence of lines.  ".
#"Physical lines may be grouped into logical lines by putting ".
#"a backslash (B<\\>) at the end.  Each physical line blah blah blah\n");

$parser->parse_lines(undef);

close $conf;
close $man;

sub read_ahead
{
	$line = <$conf>;
	if ($line)
	{
		chomp $line;
		$line =~ s/\s*$//;
	}
	else
	{
		$line = undef;
	}
}

sub skip_blanks
{
	while (defined($line) && $line eq '#')
	{
		read_ahead();
	}
}

sub mangle
{
	my $text = shift;
	$text =~ s/</E<lt</g;
	$text =~ s/>/E>gt>/g;
	$text =~ s/E[<>]([lg]t)[<>]/E<$1>/g;
	$text =~ s/\"(\S+)\"/C<$1>/g;
	return $text;
}

sub regular_text
{
	my $cnt = 0;
	while (defined($line) && $line =~ /^\#\s(\S.*\S)$/)
	{
		my $text = mangle($1);
		push @res, "$text \n";
		$cnt = 1;
		read_ahead();
	}
	push @res, "\n" if $cnt;
	return skip_blanks();
}

sub read_para
{
	@res = ("\n");

	while (defined($line) && $line =~ /^\#\s*([a-z0-9_]+)\s*(?:\((\w+)\))?$/)
	{
		my $rest = $2? mangle(" $2"): '';
		my $text = mangle($1);
		push @res, ("=item B<$text>$rest\n", "\n");
		read_ahead();
	}

	regular_text();

	if (defined($line) && $line =~ /^#\s{2,}\w{1,12}:/)
	{
		push @res, ("\n", "=over\n", "\n");
		while (defined($line) && $line =~ /^\#\s{2,}/)
		{
			$line =~ s/^\#\s*//;
			if ($line =~ /^(\w{1,12}):/)
			{
				my $text = mangle($1);
				push @res,  ("\n", "=item B<$text>\n", "\n");
				$line =~ s/^\w*:\s*//;
			}
			push @res, mangle("$line \n") if length($line);
			read_ahead();
		}
		push @res, ("\n", "=back\n", "\n");
		regular_text();
	}
	elsif (defined($line) && $line =~ /^\#\s\s/)
	{
		push @res, ("\n", "=over\n", "\n");
		while (defined($line) && $line =~ /^\#\s\s+/)
		{
			$line =~ s/^\#\s*//;
			my $item = '=item ';
			while ($line =~ s/\\+$//)
			{
				push @res, $item . mangle($line) ."\n";
				read_ahead();
				$line =~ s/^\#\s*//;
				$item = '';
			}
			push @res, $item . mangle($line) ."\n";
			push @res, "\n";
			read_ahead();
		}
		push @res, ("\n", "=back\n", "\n");
		my $cnt = scalar @res;
		skip_blanks();
		regular_text();
		push @res, "Z<>\n" if ($cnt == scalar @res);
	}

	while (defined($line) && $line !~ /^#/)
	{
		read_ahead();
	}

	# debug each stanza
	#print Dumper(@res), "-------\n";
	return @res;
}

1;

