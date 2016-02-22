#!/usr/bin/perl

use strict;
use warnings;
use MIME::Base64;

my $hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d';
my $b64 = encode_base64(pack('H*', $hex));
$hex    = unpack('H*', decode_base64($b64));

print "Base64:\t${b64}Hex:\t$hex\n";