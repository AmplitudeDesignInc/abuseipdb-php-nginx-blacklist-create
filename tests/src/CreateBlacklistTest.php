<?php

namespace App;

use PHPUnit\Framework\TestCase;
use App\CreateBlacklist;

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
    }
    public function testCreateNginxBlacklist()
    {
        $response = $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-response.json',
            dirname(__DIR__).'/test-local-blacklist.conf'
        );
        $this->assertStringMatchesFormatFile(
            dirname(__DIR__).'/expected-file-to-match.conf',
            file_get_contents(dirname(dirname(__DIR__)).'/nginx-abuseipdb-blacklist.conf')
        );
    }

    public function testNullResponseCreateNginxBlacklist()
    {
        $response = $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-local-blacklist.conf',
            dirname(__DIR__).'/test-null-response.json'
        );
        $this -> assertTrue(is_string($response));
    }

    public function testErrorResponseCreateNginxBlacklist()
    {
        $response = $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-error-response.json',
            dirname(__DIR__).'/test-local-blacklist.conf'
        );
        $this -> assertTrue(is_string($response));
        $this -> assertTrue(!file_exists($this -> obj ->rootPath."/abuseipdb-data.json"));
    }
    public function testNoConfidenceScoreCreateNginxBlacklist()
    {
        $response = $this -> obj -> createBlackList(
            dirname(__DIR__).'/test-abuseipdb-no-confidencescore-no-ip.json',
            dirname(__DIR__).'/test-local-blacklist.conf'
        );
        $this -> assertTrue(is_string($response));
    }

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
