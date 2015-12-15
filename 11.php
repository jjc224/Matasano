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

function random_aes_key($ksize)
{
    $chars = range(chr(0), chr(255));
    
    if($ksize > mcrypt_get_key_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB))
        echo 'Warning: ', __FUNCTION__, '() is intended for AES-128 key generation; key is too long.', PHP_EOL;
    
    for($key = '', $size = count($chars) - 1; strlen($key) < $ksize; $key .= $chars[rand(0, $size)]);
    return $key;
}

// Encrypts data using an unknown/random key and mode (AES-128) - also encapsulated in random data.
function encryption_oracle($data, $iv = '')
{
    $modes = array('ecb', 'cbc');
    $key   = random_aes_key(32);
    $data  = random_aes_key(rand(5, 10)) . $data . random_aes_key(rand(5, 10));
    
    return ($modes[rand(0, 1)] == 'ecb') ? mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, 'ecb') : encrypt_aes_cbc($key, $data, random_aes_key(16));
}

// Attempts to determine block cipher mode based on duplicate blocks (or lack of) - (requires repitition).
function detect_aes_mode($data)
{
    $blocks = str_split($data, mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB));
    return (count(array_unique($blocks)) < count($blocks)) ? 'ecb' : 'cbc';
}

function pad_pkcs7($string)
{
    $bsize   = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
    $padding = $bsize - (strlen($string) % $bsize);
    $string .= str_repeat(chr($padding), $padding);

    return $string;
}

$enc  = base64_encode(encryption_oracle('The YELLOW SUBMARINE is a great friend, the YELLOW SUBMARINE itself is great. All hail, the YELLOW SUBMARINE.'));
$mode = strtoupper(detect_aes_mode($enc));

echo "Ciphertext: $enc", PHP_EOL, "Mode: $mode", PHP_EOL;

?>