#!/usr/bin/php
<?php

require_once __DIR__."/config.php";
require_once __DIR__."/app/CreateBlacklist.php";

exec("curl -G https://api.abuseipdb.com/api/v2/blacklist \
  -d countMinimum=15 \
  -d maxAgeInDays=60 \
  -d confidenceMinimum=".ABUSE_CONFIDENCE_SCORE." \
  -H \"Key: ".ABUSE_IP_DB_KEY."\" \
  -H \"Accept: application/json\" > abuseipdb-data.json");

$createBlackList = new App\CreateBlacklist();
$createBlackList -> rootPath = __DIR__;
print $createBlackList -> createBlackList(__DIR__.'/abuseipdb-data.json', __DIR__.'/local-blacklist.conf');
