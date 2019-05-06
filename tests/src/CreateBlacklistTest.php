<?php

namespace App;

use PHPUnit\Framework\TestCase;
use App\CreateBlacklist;

function is_readable($filename)
{
    if (strpos($filename, 'unreadable') !== false) {
        return false;
    }
    return true;
}

class CreateBlacklistTest extends TestCase
{
    /**
     * The object under test.
     * @var CreateBlacklist
     */
    private $obj;

    public function setup()
    {
        $this -> obj = new CreateBlacklist();
        $this -> obj -> rootPath = dirname(dirname(__DIR__));
        file_put_contents(dirname(__DIR__)."/local-blacklist-unreadable-data.conf", "");

        file_put_contents(dirname(__DIR__)."/abuseipdb-blacklist-unreadable-data.json", "");
    }

    public function tearDown()
    {
        unlink(dirname(__DIR__)."/local-blacklist-unreadable-data.conf");
        unlink(dirname(__DIR__)."/abuseipdb-blacklist-unreadable-data.json");
    }

    /**
     * This is the positive AbuseIPDB response test.
     * @return null
     */
    public function testCreateNginxBlacklist()
    {
        $this -> assertTrue(false);
        $response = $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-response.json',
            dirname(__DIR__).'/test-local-blacklist.conf'
        );
        $this->assertStringMatchesFormatFile(
            dirname(__DIR__).'/expected-file-to-match.conf',
            file_get_contents(dirname(dirname(__DIR__)).'/nginx-abuseipdb-blacklist.conf')
        );
        $this -> assertTrue(is_string($response));

        //  Check that the file was removed.
        $this -> assertTrue(!file_exists($this -> obj -> rootPath."/abuseipdb-data.json"));
    }

    /**
     * This is the positive AbuseIPDB response test.
     * @return null
     */
    public function testMissingCustomNginxBlacklist()
    {
        $this -> expectException('\Exception');
        $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-response.jsonlj',
            dirname(__DIR__).'/test-local-blacklistasdf.conf'
        );
    }

    /**
     * Tests if the response is null from AbuseIPDB
     * @return null
     */
    public function testNullResponseCreateNginxBlacklist()
    {
        $this -> expectException('\Exception');
        $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-null-response.json',
            dirname(__DIR__).'/test-local-blacklist.conf'
        );
    }

    /**
     * This tests if the AbuseIPDB returns errors.
     * @return null
     */
    public function testErrorResponseCreateNginxBlacklist()
    {
        $this -> expectException('\Exception');
        $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-error-response.json',
            dirname(__DIR__).'/test-local-blacklist.conf'
        );
    }

    /**
     * Tests if there is not confidence score (edge case).
     * @return null
     */
    public function testNoConfidenceScoreCreateNginxBlacklist()
    {
        $response = $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-no-confidencescore-no-ip.json',
            dirname(__DIR__).'/test-local-blacklist.conf'
        );
        $this -> assertTrue(is_string($response));
    }

    /**
     * Test for when the local blacklist file isn't readable.
     * @return null
     */
    public function testCheckLocalBlacklistPath()
    {
        $this -> expectException('\Exception');
        $response = $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-response.json',
            dirname(__DIR__)."/local-blacklist-unreadable-data.conf"
        );
    }

    /**
     * Test for when the AbuseIPDB file isn't readable.
     * @return null
     */
    public function testCheckAbuseIpDbJsonFilePathNotFound()
    {
        $this -> expectException('\Exception');
        $response = $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-notfound-response.json',
            dirname(__DIR__).'/test-local-blacklist.conf'
        );
    }

    /**
     * Test for when the AbuseIPDB file isn't readable.
     * @return null
     */
    public function testCheckAbuseIpDbJsonFilePathNotReadable()
    {
        $this -> expectException('\Exception');
        $this -> obj -> createBlackList(
            dirname(__DIR__)."/abuseipdb-blacklist-unreadable-data.json",
            dirname(__DIR__)."/test-local-blacklist.conf"
        );
    }

    public function testCannotPutFileForOutput()
    {
        $this -> expectException('\Exception');
        $this -> obj -> rootPath = "/blashs";
        $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-response.json',
            dirname(__DIR__).'/test-local-blacklist.conf'
        );
    }

    /**
     * Tests the unlinkAbuseIpDbResponseFile method.
     * @return null
     */
    public function testUnlinkAbuseIpDbResponseFile()
    {
        file_put_contents($this -> obj -> rootPath."/abuseipdb-data.json", "");
        $response = $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-response.json',
            dirname(__DIR__).'/test-local-blacklist.conf'
        );
        $this -> assertTrue(!file_exists($this -> obj -> rootPath."/abuseipdb-data.json"));
    }
}
