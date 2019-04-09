#!/usr/bin/php
<?php

require_once __DIR__."/config.php";
require_once __DIR__."/functions/createBlackList.php";

exec("curl -G https://api.abuseipdb.com/api/v2/blacklist \
  -d countMinimum=15 \
  -d maxAgeInDays=60 \
  -d confidenceMinimum=".ABUSE_CONFIDENCE_SCORE." \
  -H \"Key: ".ABUSE_IP_DB_KEY."\" \
  -H \"Accept: application/json\" > abuseipdb-data.json");

print createBlackList(__DIR__.'/tests/test-response.json', __DIR__.'/local-blacklist.conf');

//print createBlackList(__DIR__.'/abuseipdb-data.json', , __DIR__.'/local-blacklist.conf');
