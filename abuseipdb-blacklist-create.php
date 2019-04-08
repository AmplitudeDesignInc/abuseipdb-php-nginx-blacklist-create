#!/usr/bin/php
<?php

require_once __DIR__."/config.php";

exec("curl -G https://api.abuseipdb.com/api/v2/blacklist \
  -d countMinimum=15 \
  -d maxAgeInDays=60 \
  -d confidenceMinimum=".ABUSE_CONFIDENCE_SCORE." \
  -H \"Key: ".ABUSE_IP_DB_KEY."\" \
  -H \"Accept: application/json\" > abuseipdb-data.json");

$fileContents = file_get_contents(__DIR__."/abuseipdb-data.json");

$object = json_decode($fileContents);

// Print errors and exit the script if there was a problem with the request.
if (isset($object -> errors) || !$object || empty($object)) {
    print PHP_EOL.$object -> errors[0] -> detail.PHP_EOL.PHP_EOL;
    unlink(__DIR__."/abuseipdb-data.json");
    exit;
}

$response = null;
// $allIps is used to contain all unique IPs.
$allIps = [];

// Load the local blacklist if it is available.
if (file_exists(__DIR__."/local-blacklist.conf") && is_file(__DIR__."/local-blacklist.conf")) {
    $localBlacklist = file_get_contents(__DIR__."/local-blacklist.conf").PHP_EOL;
    // Create an array exploded by a new line.
    $newLineArray = explode(PHP_EOL, $response);
    // If this is a commented line then continue.
    foreach ($newLineArray as $key => $line) {
        if (substr($line, 0, 1) === "#" || strlen($line) === 0) {
            continue;
        }
        // Get just the IP address from the line.
        $justIpAddress = str_replace(["deny", ";", " "], ["", "", ""], $line);
        // Add the ip to the all IPs array.
        if (!array_key_exists($justIpAddress, $allIps)) {
            $response .= "deny ".$justIpAddress.";".PHP_EOL;
        }
        $allIps[$justIpAddress] = $justIpAddress;
    }
}

$count = 0;
foreach ($object -> data as $key => $values) {
    if (!isset($values -> abuseConfidenceScore) || !isset($value -> ipAddress)) {
        continue;
    }
    if ($values -> abuseConfidenceScore >= ABUSE_CONFIDENCE_SCORE && !in_array($values -> ipAddress, $allIps)) {
        $response .= "deny ".$values -> ipAddress.";".PHP_EOL;
        $count++;
    }
}

file_put_contents(__DIR__."/nginx-abuseipdb-blacklist.conf", $response);

unlink(__DIR__."/abuseipdb-data.json");
print PHP_EOL;
print PHP_EOL;
print "Added ".$count." ip addresses to your blacklist.".PHP_EOL;
print "You can now test the configuration: nginx -t".PHP_EOL;
print "You will also want to reload nginx. For example, sudo service nginx reload on Ubuntu.".PHP_EOL;
