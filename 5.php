<?php

$string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
$key	= 'ICE';
$split  = str_split($string, 3);

foreach($split as $chars)
	echo bin2hex($chars ^ $key);
	
?>