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
     * The array of all IPs to use for filtering duplicates.
     * @var array
     */
    private $allIps = [];

    /**
     * The string for the final deny list.
     * @var string
     */
    public $denyListOutput = null;

    /**
     * The total count of the IPs added to the list.
     * @var integer
     */
    private $count = 0;

    /**
     * Creates the blacklist file.
     * @param  string $abuseIpDbJsonFilePath    The full path to the file containing the AbuseIPDB response.
     * @param  string $localCustomBlacklistPath The full path to the local custom file containing deny statements.
     * @return string                           The string response.
     */
    public function createBlacklist($abuseIpDbJsonFilePath, $localCustomBlacklistPath)
    {
        $responseString = null;
        $fileContents = file_get_contents($abuseIpDbJsonFilePath);
        $object = json_decode($fileContents);

        if (is_null($object)) {
            $responseString = "The json response could not be decoded.".PHP_EOL;
            return $responseString;
        }

        // Print errors and exit the script if there was are errors in the response.
        if (isset($object -> errors) || !$object || empty($object)) {
            $responseString = PHP_EOL.$object -> errors[0] -> detail.PHP_EOL.PHP_EOL;
            $this -> unlinkAbuseIpDbResponseFile();
            return $responseString;
        }

        // Load the local blacklist if it is available.
        if (file_exists($localCustomBlacklistPath) && is_file($localCustomBlacklistPath)) {
            $localBlacklist = file_get_contents($localCustomBlacklistPath).PHP_EOL;
            // Create an array exploded by a new line.
            $newLineArray = explode(PHP_EOL, $localBlacklist);

            if (is_array($newLineArray)) {
                // If this is a commented line then continue.
                array_map([$this, 'getCustomDenyList'], $newLineArray);
            }
        }

        // Handle the AbuseIpDb $object -> data.
        array_map([$this, 'getAbuseIpDbDenyList'], $object -> data);

        file_put_contents($this->rootPath."/nginx-abuseipdb-blacklist.conf", $this -> denyListOutput);
        if (file_exists($this->rootPath."/abuseipdb-data.json")
            && is_file($this->rootPath."/abuseipdb-data.json")
        ) {
            $this -> unlinkAbuseIpDbResponseFile();
        }
        $responseString .= PHP_EOL;
        $responseString .= PHP_EOL;
        $responseString .= "Added ".$this -> count." ip addresses to your blacklist.".PHP_EOL;
        $responseString .= "You can now test the configuration: nginx -t".PHP_EOL;
        $responseString .= "You will also want to reload nginx. For example, sudo service nginx reload on Ubuntu.".PHP_EOL;

        return $responseString;
    }

    /**
     * Use with array_map to get the AbuseIpDB deny list.
     * @param  array $ipObject The IP address object.
     * @return null
     */
    private function getAbuseIpDbDenyList($ipObject)
    {
        if (!property_exists($ipObject, 'abuseConfidenceScore')
            || !property_exists($ipObject, 'ipAddress')
        ) {
            return;
        }
        if ($ipObject -> abuseConfidenceScore >= ABUSE_CONFIDENCE_SCORE
            && !in_array($ipObject -> ipAddress, $this -> allIps)
        ) {
            $this -> denyListOutput .= "deny ".$ipObject -> ipAddress.";".PHP_EOL;
            $this -> count++;
        }
    }

    /**
     * Used with the array_map to filter the custom deny list.
     * @param  string $line The singular line from the custom blacklist.
     * @return null
     */
    private function getCustomDenyList($line)
    {
        if (substr(trim($line), 0, 1) === "#" || strlen(trim($line)) === 0) {
            return;
        }
        // Get just the IP address from the line.
        $justIpAddress = $this -> filterJustIp($line);
        // Add the ip to the all IPs array.
        if (!array_key_exists($justIpAddress, $this -> allIps)) {
            // Add the ip to the response string.
            $this -> denyListOutput .= "deny ".$justIpAddress.";".PHP_EOL;
            $this -> count++;
        }
        $this -> allIps[$justIpAddress] = $justIpAddress;
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
