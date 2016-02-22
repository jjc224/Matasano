<?php

$url = 'http://gist.github.com/tqbf/3132928/raw/6f74d4131d02dee3dd0766bd99a6b46c965491cc/gistfile1.txt';

$enc = explode("\n", file_get_contents($url));
$enc = array_map(function($str) { return str_split($str, mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB)); }, $enc);

foreach($enc as $blocks)
{   
    if(count(array_unique($blocks)) < count($blocks))
    {
    	echo implode('', $blocks), PHP_EOL;
    	break;
    }
}

?>