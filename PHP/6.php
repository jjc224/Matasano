<?php

function hamdist($a, $b)
{
    $func = function ($char) { return str_split(sprintf('%08b', ord($char))); };

    $a = array_map($func, str_split($a));
    $b = array_map($func, str_split($b));

    for($dist = $i = 0, $len = count($a); $i < $len; $i++)
    {
        for($j = 0, $len2 = count($a[$i]); $j < $len2; $j++)
            if($a[$i][$j] != $b[$i][$j]) $dist++;
    }

    return $dist;
}

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


$enc = 'http://gist.github.com/tqbf/3132752/raw/cecdb818e3ee4f5dda6f0847bfd90a83edb87e73/gistfile1.txt';
$enc = base64_decode(file_get_contents($enc));

for($keysize = 2; $keysize <= 40; $keysize++)
{
    $blockA = substr($enc, 0,            $keysize);
    $blockB = substr($enc, $keysize,     $keysize);
    $blockC = substr($enc, $keysize * 2, $keysize);
    $blockD = substr($enc, $keysize * 3, $keysize);

    $lenA   = strlen($blockA);
    $lenB   = strlen($blockB);
    $lenC   = strlen($blockC);
    $lenD   = strlen($blockD);
    
    if(($lenA != $lenB) || ($lenB != $lenC) || ($lenC != $lenD))
        die('Block sizes differ.');
        
    printf("(Keysize = %d)\t%.2f\n", $keysize, ((hamdist($blockA, $blockB) / $keysize) + (hamdist($blockC, $blockD) / $keysize)));
}

$keysize    = 5;
$enc_blocks = str_split($enc, $keysize);

for($i = 0; $i < $keysize; $i++)
{
    foreach($enc_blocks as $block)
        $bytes[] = bin2hex(substr($block, $i, 1));
        
    $string = implode('', $bytes);
    $unique = array_unique(array_filter($bytes));

    printf("\n\n-- Block %d --\n0x%s\n\n", ($i + 1), $string);
    score($string, $unique, $keysize, ' eta', 'bin2hex');
    
    unset($bytes);
}

?>