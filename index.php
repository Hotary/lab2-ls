<?php 

$signs = array
(
	'/(admin|sql|console)[^"]* ((?!200).)* 0/',						// подозрительные админ-панели без кода 200
	'/"(([^"]*(python|urllib|postman|nmap)[^"]*)|-)"$/',			// подозрительные useragent
	'/[0-9]{3} [0-9]+ "(-| |)"/',									// пустой refer
	'/(\\x[0-9A-F]{2})+/',											// hex-последовательности
	'/"((?!(GET|POST|HEAD|PROPFIND|OPTIONS)).)+[^"]*" [0-9]{3}/'	// нестандартное тело запроса (неверный метод или же без метода)
);

$ips = array();
$warnings = array();

$file = fopen(__DIR__ . '/access.log', 'r');

while (!feof($file)) {
	$str = fgets($file);
	$isMatched = preg_match('/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/', $str, $matches);
	$ip = $matches[0];
	
	if (array_key_exists($ip,$ips))
	{
		$ips[$ip] += 1;
	}else{
		$ips[$ip] = 1;
	}
	
	$count = 0;
	
	foreach ($signs as $sign)
	{$isMatched = preg_match($sign, $str);
		if ($isMatched)
		{
			$count += 1;
		}	
	}
	
	if ($count >= 2)
	{
		if (array_key_exists($ip,$warnings))
		{
			$warnings[$ip] += 1;
		}else{
			$warnings[$ip] = 1;
		}
		echo '<p style="color: red;">Warning: ';
		echo $str;
		echo '</p>';
	}
}

echo '<p>TOP10 ip-адресов:';

arsort($ips);
$ips = array_slice($ips, 0, 10); 
foreach ($ips as $ip => $count) {
	if (array_key_exists($ip,$warnings))
	{
		echo "<p style=\"color: red;\">[$ip] => ", $count, " count; warnings:", $warnings[$ip], "</p>";
	}
	else
	{
		echo "<p style=\"color: green;\">[$ip] => ", $count, " count</p>";
	}
}
	
?>