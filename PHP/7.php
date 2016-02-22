<?php

$url = 'http://gist.github.com/tqbf/3132853/raw/c02ff8a08ccf872f4cd278396379f4bb1ef337d8/gistfile1.txt';

$enc = base64_decode(file_get_contents($url));
$dec = mcrypt_ecb(MCRYPT_RIJNDAEL_128, 'YELLOW SUBMARINE', $enc, MCRYPT_DECRYPT);

echo $dec;

?>