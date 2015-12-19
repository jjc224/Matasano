<?php

function encrypt_aes_cbc($key, $data, $iv = '')
{   
    // mcrypt pads with null bytes, but Matasano implies desire for implementation of PKCS#7.
    
    $ksize   = mcrypt_get_key_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    $bsize   = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
    $padding = $bsize - (strlen($data) % $bsize);
    $data   .= str_repeat(chr($padding), $padding);
    
    if($iv == '')
        $iv = str_repeat("\0", $bsize);
    
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
    
    return strip_pkcs7($dec);
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

// $enc = base64_decode(file_get_contents('http://gist.github.com/tqbf/3132976/raw/f0802a5bc9ffa2a69cd92c981438399d4ce1b8e4/gistfile1.txt'));
// $dec = decrypt_aes_cbc('YELLOW SUBMARINE', $enc);

// echo $dec;

?>
