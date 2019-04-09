<?php

namespace App;

/**
 * Class that creates the blacklist and cleans up files.
 */
class CreateBlacklist
{
    /**
     * The root path to the directory where abuseipdb-blacklist-create.php is located.
     * @var string
     */
    public $rootPath;


    /**
     * Creates the blacklist file.
     * @param  string $responseFilePath   The full path to the file containing the AbuseIPDB response.
     * @param  string $localBlacklistPath The full path to the local custom file containing deny statements.
     * @return string                     The string response.
     */
    public function createBlacklist($responseFilePath, $localBlacklistPath)
    {
        $responseString = null;
        $fileContents = file_get_contents($responseFilePath);
        $object = json_decode($fileContents);
        $response = null;
        // $allIps is used to contain all unique IPs.
        $allIps = [];
        $count = 0;

        if (is_null($object)) {
            $responseString = "The json response could not be decoded.".PHP_EOL;
            return $responseString;
        }

        // Print errors and exit the script if there was a problem with the request.
        if (isset($object -> errors) || !$object || empty($object)) {
            $responseString = PHP_EOL.$object -> errors[0] -> detail.PHP_EOL.PHP_EOL;
            $this -> unlinkAbuseIpDbResponseFile();
            return $responseString;
        }

        // Load the local blacklist if it is available.
        if (file_exists($localBlacklistPath) && is_file($localBlacklistPath)) {
            $localBlacklist = file_get_contents($localBlacklistPath).PHP_EOL;
            // Create an array exploded by a new line.
            $newLineArray = explode(PHP_EOL, $localBlacklist);
            // If this is a commented line then continue.
            foreach ($newLineArray as $key => $line) {
                if (substr($line, 0, 1) === "#" || strlen($line) === 0) {
                    continue;
                }
                // Get just the IP address from the line.
                $justIpAddress = $this -> filterJustIp($line);
                // Add the ip to the all IPs array.
                if (!array_key_exists($justIpAddress, $allIps)) {
                    $response .= "deny ".$justIpAddress.";".PHP_EOL;
                    $count++;
                }
                $allIps[$justIpAddress] = $justIpAddress;
            }
        }

        foreach ($object -> data as $key => $values) {
            if (!property_exists($values, 'abuseConfidenceScore')
                || !property_exists($values, 'ipAddress')
            ) {
                continue;
            }
            if ($values -> abuseConfidenceScore >= ABUSE_CONFIDENCE_SCORE
                && !in_array($values -> ipAddress, $allIps)
            ) {
                $response .= "deny ".$values -> ipAddress.";".PHP_EOL;
                $count++;
            }
        }

        file_put_contents($this->rootPath."/nginx-abuseipdb-blacklist.conf", $response);
        if (file_exists($this->rootPath."/abuseipdb-data.json")
            && is_file($this->rootPath."/abuseipdb-data.json")
        ) {
            $this -> unlinkAbuseIpDbResponseFile();
        }
        $responseString .= PHP_EOL;
        $responseString .= PHP_EOL;
        $responseString .= "Added ".$count." ip addresses to your blacklist.".PHP_EOL;
        $responseString .= "You can now test the configuration: nginx -t".PHP_EOL;
        $responseString .= "You will also want to reload nginx. For example, sudo service nginx reload on Ubuntu.".PHP_EOL;

        return $responseString;
    }

    /**
     * Gets just the ip address from a string.
     * @param  string $string The ip address string to filter: deny 00.00.00.00;
     * @return string         The filtered ip address.
     */
    private function filterJustIp($string)
    {
        return str_replace(["deny", ";", " "], ["", "", ""], $string);
    }

    /**
     * Removes the file created from the API request.
     * @return null
     */
    private function unlinkAbuseIpDbResponseFile()
    {
        if (!file_exists($this->rootPath."/abuseipdb-data.json")) {
            return;
        }
        unlink($this->rootPath."/abuseipdb-data.json");
    }
}
