<?php

function xor_hex($hex, $hex2)
{
	if(strlen($hex) != strlen($hex2))
		return 'Buffer lengths differ.';
	
	return bin2hex(hex2bin($hex) ^ hex2bin($hex2));
}

echo xor_hex('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965');

?>