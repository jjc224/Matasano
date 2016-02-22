<?php

function strip_pkcs7($padded_str)
{
    $len = strlen($padded_str);
    $pad = ord($padded_str[$len-1]);
    
    if(substr($padded_str, $len - $pad) != str_repeat(chr($pad), $pad))
        throw new Exception(__FUNCTION__ . '(): Bad padding.');
        
    return substr($padded_str, 0, $len - $pad);
}

function pad_pkcs7($string)
{
	$bsize   = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
	$padding = $bsize - (strlen($string) % $bsize);
	$string .= str_repeat(chr($padding), $padding);

	return $string;
}

$padded = pad_pkcs7('BANKAI!');

try
{
    echo strip_pkcs7($padded);
}
catch(Exception $e)
{
    echo $e->getMessage(), PHP_EOL;
}

?>