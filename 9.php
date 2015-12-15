<?php

$string  = 'BANKAI!';
$bsize   = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
$padding = $bsize - (strlen($string) % $bsize);
$string .= str_repeat(chr($padding), $padding);

echo $string;

?>