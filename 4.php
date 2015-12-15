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


$list = 'http://gist.github.com/tqbf/3132713/raw/40da378d42026a0731ee1cd0b2bd50f66aabac5b/gistfile1.txt';
$list = explode("\n", file_get_contents($list));

foreach($list as $enc)
{
	$bytes		 = str_split($enc, 2);
	$occur[$enc] = max(array_count_values($bytes));
}


$new = array_keys($occur, max($occur));
unset($occur);

foreach($new as $enc)
{
	$bytes   = str_split($enc, 2);
	$occur[] = array_values(array_count_values($bytes));
}

rsort($occur[0]);
rsort($occur[1]);

$enc    = ($occur[0][0] + $occur[0][1] > $occur[1][0] + $occur[1][1]) ? $new[0] : $new[1];
$unique = array_unique(str_split($enc, 2));

echo "Encrypted: $enc", PHP_EOL;
score($enc, $unique, 1, ' eta');

?>