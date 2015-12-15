<?php

function random_aes_key($ksize)
{
    $chars = range(chr(0), chr(255));
    
    if($ksize > mcrypt_get_key_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB))
        echo 'Warning: ', __FUNCTION__, '() is intended for AES-128 key generation; key is too long.', PHP_EOL;
    
    for($key = '', $size = count($chars) - 1; strlen($key) < $ksize; $key .= $chars[rand(0, $size)]);
    return $key;
}

function encrypt_aes_ecb($data, $key)
{
    $data .= base64_decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK');
    return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, 'ecb');
}

// Attempts to determine block cipher mode based on duplicate blocks (or lack of) - (requires repitition).
function detect_aes_mode($data)
{
    $blocks = str_split($data, mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB));
    return (count(array_unique($blocks)) < count($blocks)) ? 'ecb' : 'cbc';
}


$key = random_aes_key(16);

// Determines block-size of padded ciphertext by invoking the pad function and monitoring the result.
for($s = 'A', $j = strlen(encrypt_aes_ecb($s, $key)); ($k = strlen(encrypt_aes_ecb($s, $key))) == $j; $s .= 'A');

$bsize  = $k - $j;
$mode   = detect_aes_mode(encrypt_aes_ecb(str_repeat('A', $bsize * 2), $key));
$chars  = range(chr(0), chr(255));


echo "Block size: $bsize\nCipher mode: $mode\n\n";

for($i = 0, $j = 1, $end = $bsize, $dec = ''; $i < $end; $i++, $j++)
{
    $str   = str_repeat('A', $bsize - $j);
    $block = substr(encrypt_aes_ecb($str, $key), 0, $end);
    $str2  = $str . $dec;
    
    foreach($chars as $char)
        $dict[$char] = substr(encrypt_aes_ecb($str2 . $char, $key), 0, $end);
   
    if(in_array($block, $dict))
    {
        $char = array_search($block, $dict);
        $dec .= $char;
        
        echo $char;
    }
        
    if(strlen($dec) % $bsize == 0)
    {
        $j    = 0;
        $end += $bsize;
    }
}

?>