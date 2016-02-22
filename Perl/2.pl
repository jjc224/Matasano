#!/usr/bin/perl -w

print xor_hex('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965');

sub xor_hex
{
    return 'Buffer lengths differ.' if length($_[0]) != length($_[1]);
    return unpack('H*', pack('H*', $_[0]) ^ pack('H*', $_[1]));
}