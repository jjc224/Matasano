<?php

$hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d';
$b64 = base64_encode(hex2bin($hex));
$hex = bin2hex(base64_decode($b64));

echo "Base64:\t$b64\nHex:\t$hex";

// "I'm killing your brain like a poisonous mushroom" pls no. ;c

?>