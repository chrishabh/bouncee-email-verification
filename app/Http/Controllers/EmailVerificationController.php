<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Exception;

class EmailVerificationController extends Controller
{
    public function verify(Request $request)
    {
        $email = $request->query('email');

        If(!$email){
            return response()->json(['message' => 'Email is required'], 1400);
        }

        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json(['email' => $email, 'status' => 'Invalid', 'reason' => 'Invalid email format'], 200);
        }

        // Extract domain
        $domain = substr(strrchr($email, "@"), 1);

        // Get MX records
        $mxRecords = dns_get_record($domain, DNS_MX);
        if (!$mxRecords) {
            return response()->json(['email' => $email, 'status' => 'undeliverable', 'reason' => 'No MX records found'], 200);
        }

        $mxServer = $mxRecords[0]['target'];

        // Perform SMTP Handshake
        $smtpResponse = $this->telnetsmtpHandshake($email, $mxServer);

        if(isset($smtpResponse['status']) && isset($smtpResponse['data'])) {
            return response()->json([
                'email' => $email,
                'mx-record' => $mxServer,
                'status' => $smtpResponse['status'],
                'reason' => $smtpResponse['data']
            ],200);
          
        }else{
            return response()->json([
               'message' => $smtpResponse
            ],1400);
        }
    }

    private function telnetsmtpHandshake($email, $mxServer)
    {
        try {
            $connection = @fsockopen($mxServer, 25, $errno, $errstr, 10);
        
            if (!$connection) {
                throw new Exception("Failed to connect to SMTP server: $errstr ($errno)");
            }
        
            $responses = [];
            stream_set_timeout($connection, 10);
        
            // Read the initial 220 response
            $initialResponse = fgets($connection, 1024);
            if (!$initialResponse || strpos($initialResponse, '220') !== 0) {
                throw new Exception("Unexpected SMTP response: " . trim($initialResponse));
            }
            $responses[] = trim($initialResponse);
        
            // Send EHLO
            $smtpDomain = env('SMTP_DOMAIN');
            fwrite($connection, "EHLO $smtpDomain\r\n");
            $ehloResponse = fgets($connection, 1024);
            if (!$ehloResponse || strpos($ehloResponse, '250') !== 0) {
                throw new Exception("EHLO command failed: " . trim($ehloResponse));
            }
            $responses[] = trim($ehloResponse);
        
            // Read additional EHLO responses
            while (($line = fgets($connection, 1024)) !== false) {
                $responses[] = trim($line);
                if (strpos($line, '250 ') === 0) break; // Stop when the last 250 response is received
            }
        
            // Send MAIL FROM
            $fromEmail = env('SMTP_MAIL_FROM_ADDRESS');
            fwrite($connection, "MAIL FROM: <$fromEmail>\r\n");
            $mailFromResponse = fgets($connection, 1024);
            if (!$mailFromResponse || strpos($mailFromResponse, '250') !== 0) {
                throw new Exception("MAIL FROM command failed: " . trim($mailFromResponse));
            }
            $responses[] = trim($mailFromResponse);
        
            // Send RCPT TO
            fwrite($connection, "RCPT TO: <$email>\r\n");
            $rcptResponse = fgets($connection, 1024);
            if (!$rcptResponse || strpos($rcptResponse, '250') !== 0) {
                throw new Exception("RCPT TO command failed: " . trim($rcptResponse));
            }
            $responses[] = trim($rcptResponse);
        
            // Send QUIT
            fwrite($connection, "QUIT\r\n");
            fclose($connection);
        
            // **Determine email status**
            if (strpos($rcptResponse, '250') !== false) {
                return ["status" => "deliverable", "data" => $responses];
            } elseif (strpos($rcptResponse, '550-5.1.1') !== false) {
                return ["status" => "undeliverable", "data" => $responses];
            } elseif (strpos($rcptResponse, '550 5.7.1') !== false || strpos($rcptResponse, '550 5.4.1') !== false) {
                return ["status" => "bounce", "data" => $responses];
            } elseif (strpos($rcptResponse, '450') !== false || strpos($rcptResponse, '451') !== false || strpos($rcptResponse, '452') !== false) {
                return ["status" => "unknown", "data" => $responses];
            } elseif (strpos($rcptResponse, '421') !== false) {
                return ["status" => "undeliverable", "data" => $responses];
            } elseif (preg_match('/250.*catch/i', implode(" ", $responses))) {
                return ["status" => "accepted_all", "data" => $responses];
            } else {
                
            }
        } catch (Exception $e) {
            $responses[] = $e->getMessage();
            return ["status" => "unknown", "data" => $responses];
        }        

        
    }
}
