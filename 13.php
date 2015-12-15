<?php

function random_aes_key($ksize)
{
    $chars = range(chr(0), chr(255));
    
    if($ksize > mcrypt_get_key_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB))
        echo 'Warning: ', __FUNCTION__, '() is intended for AES-128 key generation; key is too long.', PHP_EOL;
    
    for($key = '', $size = count($chars) - 1; strlen($key) < $ksize; $key .= $chars[rand(0, $size)]);
    return $key;
}

function parse_profile($query)
{
    $a = explode('&', $query);

    foreach($a as $kv)
    {
        $b = explode('=', $kv);

        if(count($b) == 2)    // So 'rol' isn't shown (see comment at line 61).
            $c[$b[0]] = $b[1];
    }

    return $c;
}

function profile_for($email)
{
    $email    = preg_replace('/&|=/', '', $email);
    $uid      = 10;
    $role     = 'user';
    $kv_pairs = array('email' => $email, 'uid' => $uid, 'role' => $role);
    
    return urldecode(http_build_query($kv_pairs));
}

function encrypt_profile($query, $key)
{
    return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $query, 'ecb');   
}

function decrypt_profile($enc, $key)
{
    $dec = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $enc, 'ecb');
    return parse_profile($dec);
}

$bsize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
$key   = random_aes_key(16);
$email = 'aaaaaaa@a.com';
$evil  = str_repeat('A', 10) . 'admin';     // strlen('email=AAAAAAAAAA') == 16.

$enc  = encrypt_profile(profile_for($email), $key);
$enc2 = encrypt_profile(profile_for($evil), $key);

$blocks  = str_split($enc, $bsize);
$blocks2 = str_split($enc2, $bsize);

$evil_enc     = $blocks[0] . $blocks[1] . $blocks2[1];    // 'email=aaaaaaa@a.' + 'com&uid=10&role=' + 'admin&uid=10&rol' ($blocks2[0] is the padding/block 'email=AAAAAAAAAA').
$evil_profile = decrypt_profile($evil_enc, $key);

print_r($evil_profile);

if($evil_profile['role'] == 'admin')
    echo PHP_EOL, "You're in, 'admin'. ;~)", PHP_EOL;

?>