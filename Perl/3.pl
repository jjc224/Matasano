#!/usr/bin/perl

use warnings;
use strict;
use List::MoreUtils 'uniq';

my $enc    = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736';
my @unique = uniq($enc =~ m/../g);

score($enc, \@unique, 1, ' eta');

sub score
{
    my ($string, $unique, $length, $charset, $pretty) = @_;

    my @chars               = ($enc =~ m/../g);
    my @common              = split('', $charset);
    my %occur               = ();
    my (@occur, @key_chars) = (), ();
    
    $occur{$_} = eval "\$string =~ y/$_//" for @unique;
    #push(@occur, $_) for(sort {$occur{$b} <=> $occur{$a}} keys %occur);
    
    for @common
    {
	    for(sort {$occur{$b} <=> $occur{$a}} keys %occur);
    }
}