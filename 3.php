<?php

function score($string, $unique, $length, $charset, $pretty = '')
{   
    $chars  = str_split($string, 2);
    $common = str_split($charset);
    
    foreach($unique as $char)
	    $occur[$char] = substr_count($string, $char);
	
	arsort($occur);
	$occur = array_keys(array_slice($occur, 0, $length, true));
    
    foreach($common as $test_char)
    {
        foreach($occur as $occur_char)
            $key_chars[] = (hex2bin($occur_char) ^ $test_char);
    }
    
    $key_chars = array_unique($key_chars);
    printf("Number of possible key-chars: %d\n\n", count($key_chars));
    
    foreach($key_chars as $key_char)
    {
        printf("[Char = '%s' (0x%02x)]\t", $key_char, ord($key_char));
    
        foreach($chars as $char)
            echo $pretty ? $pretty(hex2bin($char) ^ $key_char) : (hex2bin($char) ^ $key_char);
            
        echo PHP_EOL;
    }
}


$enc    = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736';
$unique = array_unique(str_split($enc, 2));

score($enc, $unique, 1, ' eta');

?>