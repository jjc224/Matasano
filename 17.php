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

    return $dec;
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

function random_enc($key)
{
    $strings = array('MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
                     'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
                     'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
                     'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
                     'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
                     'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
                     'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
                     'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
                     'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
                     'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
        );
   
    $iv  = random_aes_key(16);
    $enc = encrypt_aes_cbc($key, base64_decode($strings[rand(0, count($strings)-1)]), $iv);

    return array($iv, $enc);
}

function valid_padding($key, $enc, $iv)
{
    $plain = decrypt_aes_cbc($key, $enc, $iv);
    $len   = strlen($plain);
    $pad   = ord($plain[$len-1]);

    return substr($plain, $len - $pad) == str_repeat(chr($pad), $pad);
}

 function get_pad_byte($key, $enc, $iv)
 {
	$bsize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
	$len   = strlen($enc);
	$bytes = range(0, 255);

//	if($len == $bsize)    // A single block.

	for($i = 1; $i < $len; $i++)
	{
		echo "Currently at: $i\n";

		for($j = 0, $k = count($bytes); $j < $k; $j++)
		{
			$evil = str_repeat("\x00", $len - $bsize - $i) . $bytes[$j] . str_repeat("\x00", $bsize + $i - 1);

			if(valid_padding($key, $enc ^ $evil, $iv))
				return array($i, chr($bytes[$j]));
		}
	}

	return 'FUCK';
 }


$bsize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
$key = random_aes_key(16);
$enc = random_enc($key);
$iv  = $enc[0];
$enc = $enc[1];
$len = strlen($enc);
// $evil = str_repeat('\0', $len - $bsize - 5) . 0x00 . str_repeat('\0', $bsize + 4);
$evil = str_repeat("\x00", $len - $bsize - 6) . 0x01 . str_repeat("\x00", $bsize + 5);

$pad_byte = get_pad_byte($key, $enc, $iv);
die(var_dump(ord($pad_byte[1]), $pad_byte[1], $pad_byte[0]));

if(valid_padding($key, $enc ^ $evil, $iv))
    echo 'Valid padding.';
else
    echo 'Invalid padding.';
 
echo PHP_EOL;

?>
