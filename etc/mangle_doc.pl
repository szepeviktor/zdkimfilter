#! /usr/bin/perl
use strict;
use warnings;

use HTML::PullParser;
use Data::Dumper;
use File::Slurp qw(slurp);

# Pipe as, e.g.: man2html zdkimfilter.conf.5 | perl mangle_doc.pl h1
# or groff -T xhtml -mandoc zdkimfilter.8 | perl mangle_doc.pl title
# or cat my-html | perl mangle_doc.pl web 1 > temp; cp temp my-html 

my $outdir = '/export/web/root/home/www/sw/zdkimfilter/';

# targets by menu position, as used in open_target below.
my @docs = (
	['zdkimfilter', 'ZDKIMFILTER(8)', 'zdkimfilter.html'],
	['dkimsign', 'DKIMSIGN(1)','dkimsign.html'],
	['redact', 'REDACT(1)','redact.html'],
	['zaggregate', 'ZAGGREGATE(1)','zaggregate.html'],
	['zfilter_db', 'ZFILTER_DB(1)', 'zfilter_db.html'],
	['zdkimfilter.conf', 'ZDKIMFILTER.CONF(5)', 'zdkimfilter.conf.html']);
my @web = (
	['home', 'ZDKIMFILTER', '/sw/zdkimfilter/'],
	['old', 'OLD ZDKIMFILTER', 'v-0.5.shtml'],
	['db', 'Database', 'database.html']);

# 

my $mode = $ARGV[0];
if (!defined($mode) || ($mode ne 'h1' and $mode ne 'title' and $mode ne 'web'))
{
	print "Invalid arg $mode, using \"title\"\n" if defined($mode);
	$mode = 'title';
}

my $webvariant;
my $snippet;

if (defined($ARGV[1]))
{
	if ($mode eq 'web') {$webvariant = $ARGV[1];}
	else {$snippet = slurp($ARGV[1]);}
}

my $title;
my $outfile;

sub open_target
{
	my $js = shift;
	my $i;
	my $decla = '';
	my $oldstyle = '';
	if ($mode eq 'web')
	{
		open $outfile, ">&STDOUT" or die "Can't reopen STDOUT: $!";
		$i = $webvariant;
		$title = $web[$i][1];
		if ($web[$i][0] eq 'old')
		{
			$decla =
			' PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/REC-html40/loose.dtd"';
			$oldstyle = '
	<link href="zdkimfilter.css" rel="stylesheet" type="text/css" media="screen">';
		}
	}
	else
	{
		return unless defined $title;

		$title =~ s/^\s+|\s+$//g;
		for ($i = 0; $i < @docs; ++$i)
		{
			last if $docs[$i][0] eq $title;
		}
	
		die "unknown document: $title" unless $i < @docs;
		my $outname = $outdir . $docs[$i][2];
		open $outfile, ">$outname" or die "Can't open $outname: $!";
		print 'Opened ', $outname, "\n";
		$title = $docs[$i][1];
	}

	print $outfile '<!DOCTYPE HTML', $decla, '>
<html>
<head>
   <meta name="KeyWords" content="courier, Courier-MTA, DKIM, DMARC, filter, C, zdkimfilter, sign, verify">
   <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
   <title>', $title, '</title>
	<link href="/site.css" rel="stylesheet" type="text/css" media="screen">
	<link href="z.css" rel="stylesheet" type="text/css" media="screen">', $oldstyle, $js, '
</head>
<body>
<div id="topbar">';
	for (my $w = 0; $w < @web; ++$w)
	{
		if ($w == $i and $mode eq 'web')
		{
			print $outfile '<span class="toploaded">', $web[$i][0], "\n  ", '</span>';
		}
		else
		{
			print $outfile '<span class="topbutton">', "\n ",
				'<a href="', $web[$w][2], '">', $web[$w][0], '</a></span>';
		}
	}
	print $outfile "\n ",
		'<div class="buttongroup"><span class="grouplabel">documentation:</span>';
	for (my $w = 0; $w < @docs; ++$w)
	{
		if ($w == $i and $mode ne 'web')
		{
			print $outfile '<span class="grouploaded">', $docs[$i][0], "\n  ", '</span>';
		}
		else
		{
			print $outfile '<span class="groupbutton"><a href="',
				$docs[$w][2], '">', $docs[$w][0], '</a>', "\n  ", '</span>';
		}
	}
	print $outfile "\n ", '</div>', "\n", '</div>', "\n";
	if ($mode ne 'web')
	{
		print $outfile '<h1 class="doctitle">', $docs[$i][1], '</h1>', "\n";
	}
}


# find a sequence and write a snippet after it (for zfilter_db.1)
sub same_tok
{
	my ($a, $b) = @_;
	#print STDERR "a:",Dumper($a),"\nb:",Dumper($b),"\n";
	return 0 unless defined($a->[0]) && defined($b->[0]) &&
		defined($a->[3]) && defined($b->[3]);
	return ($a->[0] eq $b->[0] &&
		(!defined($a->[1]) && !defined($b->[1]) ||
			defined($a->[1]) && defined($b->[1]) && $a->[1] eq $b->[1]) &&
		$a->[3] eq $b->[3])? 1: 0;
}

my $find_sequence = 0;
my $sequence = [
	['start', 'h3', {}, '<H3>' ],
	['text', undef, undef, 'Storing outgoing messages'],
	['end', 'h3', undef, '</H3>']];

# parser

my $par = HTML::PullParser->new(file => *STDIN,
	default => 'event, tagname, attr, text') || die "Can't open: $!";

my $tok;

if ($mode eq 'web')
{
	# skip the whole head, except javascript or style
	my $what = $webvariant == '2'? 'style': 'script';
	my $js = '';
	my $in_js = 0;
	while ($tok = $par->get_token)
	{
		if ($tok->[0] eq 'start' && $tok->[1] eq $what)
		{
			$js .= "\n\t";
			$in_js = 1;
		}
		$js .= $tok->[3] if $in_js && $tok->[3];
		$in_js = 0 if ($tok->[0] eq 'end' && $tok->[1] eq $what);
		last if ($tok->[0] eq 'start' && $tok->[1] eq 'h1');
	}

	open_target($js);
	print $outfile '<h1>';

	# copy the rest
	while ($tok = $par->get_token)
	{
		print $outfile $tok->[3] if defined $tok->[3];
	}
	close($outfile);
	exit;
}

# skip until title or h1, as given in $ARGV[0]
while ($tok = $par->get_token)
{
	if ($tok->[0] eq 'start' && $tok->[1] eq $mode)
	{
		$tok = $par->get_token;
		$tok->[0] eq 'text' or die 'Missing title';
		$title = $tok->[3];
		last;
	}		
}


# skip until <hr/>
my $horizontal_rule = 0;
while ($tok = $par->get_token)
{
	if ($tok->[0] eq 'start' &&
		($tok->[1] eq 'hr/' || $tok->[1] eq 'hr'))
	{
		$horizontal_rule = 1;
		last;
	}
}

die 'missing <hr/>' unless $horizontal_rule;

open_target('');

# sed -nr 's/^.*style="([^"]*)".*/\1/p' zdkimfilter.8.xhtml |sort |uniq
my %classes = (
	'margin-left:11%;' => 'pitem',
	'margin-left:17%;' => 'p2item',
	'margin-left:23%;' => 'p3item',
	'margin-left:11%; margin-top: 1em' => 'docpara',
	'margin-left:17%; margin-top: 1em' => 'doc2para',
	'margin-left:23%; margin-top: 1em' => 'doc3para');

my $trex = qr'/(var|etc|usr)(/local)?/(courier|libexec)/';
my $hrex = qr'http://(\S+)';

my @ignored_tags = ('col', 'colgroup', 'a');
my @span_tags = ('tt', 'font');

my $is_box = 0;
sub close_box()
{
	if ($is_box)
	{
		print $outfile "</div>\n";
		$is_box = 0;
	}
}

my $is_header = 0;
my $header_text = '';
my @anchors = ();
sub close_header()
{
	print STDERR "Missed start header\n" unless $is_header;

	my $hash = lc($header_text);
	$hash =~ s/[^a-zA-Z0-9]+//g;
	$hash = substr($hash, 0, 8);
	if (length($hash) <= 4 or grep($_ eq $hash, @anchors))
	{
		print $outfile
			sprintf('<h%d>%s</h%d>',
				$is_header, $header_text, $is_header);
	}
	else
	{
		push(@anchors, $hash);
		print $outfile
			sprintf('<h%d id="%s">%s</h%d>',
				$is_header, $hash, $header_text, $is_header);
	}
	$is_header = 0;
	$header_text = '';
}


while ($tok = $par->get_token)
{
#	print STDERR Dumper($tok);
	if ($tok->[0] eq 'start')
	{
		if ($tok->[1] eq 'hr')
		{
			# skip the rest (man2html)
			while ($tok = $par->get_token)
			{
				if ($tok->[0] eq 'end' and $tok->[1] eq 'body')
				{
					$par->unget_token($tok);
					last;
				}
			}			
		}
		elsif ($tok->[1] eq 'h2')
		{
			close_box();
			$is_header = 2;
		}
		elsif ($tok->[1] =~ /h([13456])/)
		{
			$is_header = $1;
		}
		elsif ($tok->[1] eq 'p' and defined($tok->[2]{'style'}))
		{
			my $style = $tok->[2]{'style'};
			my $repl = $classes{$style};
			if (defined($repl))
			{
				print $outfile '<p class="', $repl, '">';
			}
			else
			{
				print STDERR 'Missing style: ', $style, "\n";
				print $outfile '<p>';
			}
		}
		elsif ($tok->[1] eq 'dl')
		{
			print $outfile '<dl>';
		}
		elsif (grep($_ eq $tok->[1], @span_tags))
		{
			print $outfile '<span class="is_', $tok->[1], '">';
		}
		elsif (!grep($_ eq $tok->[1], @ignored_tags))
		{
			print $outfile $tok->[3] if defined $tok->[3];
		}
	}
	elsif ($tok->[0] eq 'end')
	{
		if (grep($_ eq $tok->[1], @span_tags))
		{
			print $outfile '</span>';
		}
		elsif ($tok->[1] eq 'h2')
		{
			close_header();
			print $outfile '<div class="box">', "\n";
			$is_box = 1;
		}
		elsif ($tok->[1] =~ /h[13456]/)
		{
			close_header();
		}
		elsif ($tok->[1] eq 'body')
		{
			close_box();
			print $outfile '<p class="copy">Copyright &copy; 2012-2015 Alessandro Vesely</p>';
			print $outfile $tok->[3] if defined $tok->[3];
		}
		elsif (!grep($_ eq $tok->[1], @ignored_tags))
		{
			print $outfile $tok->[3] if defined $tok->[3];
		}
	}
	elsif ($tok->[0] eq 'text')
	{
		my $text = $tok->[3];
		$text =~ s/$trex/\/local\/$3\/$1\/path\//g;
		$text =~ s/$hrex/<a href="http:\/\/$1" target="_blank">$1<\/a>/g;
		#/
		if ($is_header)
		{
			$header_text .= $text;
		}
		else
		{
			print $outfile $text;
		}
	}
	elsif ($tok->[0] eq 'end_document')
	{
		close($outfile);
		last;
	}
	else
	{
		print STDERR 'Unexpected: ', Dumper($tok);
	}

	if (defined($snippet))
	{
		if (same_tok($tok, $sequence->[$find_sequence]))
		{
			$find_sequence += 1;
			if ($find_sequence >= 3)
			{
				print $outfile $snippet;
				undef $snippet;
			}
		}
	}
}

print STDERR "end\n";

print STDERR "missed snipped\n" if defined($snippet);

#   remove the id= from <h2
#   assign a class to the various <p style=
#   insert a <span class= after each <br/>, close it before the next (or </p>)
#   in the text replace {etc|var}/courier and similar with /local/path/


