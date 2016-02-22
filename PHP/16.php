<?php

function encrypt_aes_cbc($key, $data, $iv = '')
{   
    // mcrypt pads with null bytes, but Matasano implies desire for implementation of PKCS#7.
    
	$ksize = mcrypt_get_key_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
	$bsize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
	$data  = pad_pkcs7($data);
    
    if(strlen($iv) != $bsize)
    {
        echo 'Warning: IV must match block-size in length. Defaulting to null bytes.', PHP_EOL;
        $iv = str_repeat("\0", $bsize);
    }

    if(strlen($key) > $ksize)
        die("Error: Maximum key-size for AES-128-CBC is $ksize." . PHP_EOL);
    
    $blocks    = str_split($data, $bsize);
    $blocks[0] = mcrypt_ecb(MCRYPT_RIJNDAEL_128, $key, $blocks[0] ^ $iv, MCRYPT_ENCRYPT);
    
    for($i = 1, $j = count($blocks), $enc = $blocks[0]; $i < $j; $i++)
    {
        $blocks[$i] ^= $blocks[$i-1];
        $blocks[$i]  = mcrypt_ecb(MCRYPT_RIJNDAEL_128, $key, $blocks[$i], MCRYPT_ENCRYPT);
        
        $enc .= $blocks[$i];
    }
    
    return $enc;
}

function decrypt_aes_cbc($key, $data, $iv = '')
{    
    $ksize = mcrypt_get_key_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    $bsize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
    
    if($iv == '')
        $iv = str_repeat("\0", $bsize);
    
    if(strlen($iv) != $bsize)
    {
        echo 'Warning: IV must match block-size in length. Defaulting to null bytes.', PHP_EOL;
        $iv = str_repeat("\0", $bsize);
    }

    if(strlen($key) > $ksize)
        die("Error: Maximum key-size for AES-128-CBC is $ksize." . PHP_EOL);
        
    $blocks = str_split($data, $bsize);
    $dec    = mcrypt_ecb(MCRYPT_RIJNDAEL_128, $key, $blocks[0], MCRYPT_DECRYPT) ^ $iv;
    
    for($i = 1, $j = count($blocks); $i < $j; $i++)
	    $dec .= mcrypt_ecb(MCRYPT_RIJNDAEL_128, $key, $blocks[$i], MCRYPT_DECRYPT) ^ $blocks[$i-1];

	try
	{
	    return strip_pkcs7($dec);
	}
	catch(Exception $e)
	{
	    die($e->getMessage() . PHP_EOL);
	}
}

function random_aes_key($ksize)
{
    $chars = range(chr(0), chr(255));
    
    if($ksize > mcrypt_get_key_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB))
        echo 'Warning: ', __FUNCTION__, '() is intended for AES-128 key generation; key is too long.', PHP_EOL;
    
    for($key = '', $size = count($chars) - 1; strlen($key) < $ksize; $key .= $chars[rand(0, $size)]);
    return $key;
}

function pad_pkcs7($string)
{
	$bsize   = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
	$padding = $bsize - (strlen($string) % $bsize);
	$string .= str_repeat(chr($padding), $padding);

	return $string;
}

function strip_pkcs7($padded_str)
{
    $len = strlen($padded_str);
    $pad = ord($padded_str[$len-1]);
    
    if(substr($padded_str, $len - $pad) != str_repeat(chr($pad), $pad))
        throw new Exception(__FUNCTION__ . '(): Bad padding.');
        
    return substr($padded_str, 0, $len - $pad);
}

function aes_cbc_cookie($string, $key)
{
	$string = preg_replace('/(=|;)/', "'$1'", $string);
	$string = "comment1=cooking%20MCs;userdata={$string};comment2=%20like%20a%20pound%20of%20bacon";

	return encrypt_aes_cbc($key, $string, 'YELLOW SUBMARINE');
}

function check_cookie($enc, $key)
{
	return strpos(decrypt_aes_cbc($key, $enc, 'YELLOW SUBMARINE'), ';admin=true;') !== false;
}


$bsize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
$evil  = str_repeat('A', $bsize) . '1234;dmi=rue';    // Create a sacrificial block. The appended string ends up as the size of a single block, which is to be bit-flipped.
$key   = random_aes_key(16);
$enc   = aes_cbc_cookie($evil, $key);

$flip  = "'FIS";    // The four characters (in order) to be XOR'd with the single quotes to produce '1234;admin=true'.
$evil  = "\0\0\0\0{$flip[0]}\0{$flip[1]}\0\0\0{$flip[2]}\0{$flip[3]}\0\0\0\0";
$evil  = str_repeat("\0", $bsize * 2) . $evil . str_repeat("\0", $bsize * 4);

if(check_cookie($enc ^ $evil, $key))
	echo 'You win! :~)', PHP_EOL;

?>