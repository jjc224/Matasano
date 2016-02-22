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
    global $rand_prefix;

    $data = $rand_prefix . $data . base64_decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK');
    return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, 'ecb');
}

// Attempts to determine block cipher mode based on duplicate blocks (or lack of) - (requires repitition).
function detect_aes_mode($data)
{
    $blocks = str_split($data, mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB));
    return (count(array_unique($blocks)) < count($blocks)) ? 'ecb' : 'cbc';
}

function get_prefix_len($key)
{
    $mult  = 3;
    $bsize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);

    $enc    = encrypt_aes_ecb(str_repeat('A', $bsize * $mult), $key);
    $blocks = str_split($enc, $bsize);
    $index  = $prefix_len = 0;

    for($i = 1, $c = count($blocks); $i < $c; $i++)
    {
        if($blocks[$i] == $blocks[$i-1])
            $index = $i;
        else if($index != 0)
            break;
    }

    for($i = $bsize * $mult - 1; $i >= 0; $i--, $prefix_len++)
    {
        $enc    = encrypt_aes_ecb(str_repeat('A', $i), $key);
        $blocks = str_split($enc, $bsize);

        if($blocks[$index] != $blocks[$index-1])
        {
            $prefix_len += $bsize * ($index - $mult + 1);
            break;
        }
    }

    return $prefix_len;
}

$key         = random_aes_key(16);
$rand_prefix = random_aes_key(rand(0, 32));
$bsize       = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
$mode        = detect_aes_mode(encrypt_aes_ecb(str_repeat('A', $bsize * 2), $key));
$chars       = range(chr(0), chr(255));
$prefix_len  = get_prefix_len($key);

echo "Block size: $bsize\nRandom-prefix length: $prefix_len\nCipher mode: $mode\n\n";


// The length of the random-prefix is in the interval [0,32], so incorporate the following properties into the original attack code:
//     1. 47 ($bsize * 3 - 1) 'A's is the maximum and safest width for a mix of padding and alignment of the first byte to attack.
//     2. Skip the first 32 ($bsize * 2) bytes, as tampering of the tailing block is all that is necessary.


for($i = 0, $j = 1, $end = $bsize, $dec = ''; $i < $end; $i++, $j++)
{
    $str   = str_repeat('A', $bsize * 3 - $prefix_len - $j);
    $block = substr(encrypt_aes_ecb($str, $key), $bsize * 2, $end);
    $str2  = $str . $dec;

    foreach($chars as $char)
        $dict[$char] = substr(encrypt_aes_ecb($str2 . $char, $key), $bsize * 2, $end);
   
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