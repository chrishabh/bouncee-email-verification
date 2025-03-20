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
            return response()->json(['message' => 'Email is required'], 401);
        }

        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json(['email' => $email, 'status' => 'Invalid', 'reason' => 'Invalid email format'], 200);
        }

        // Extract domain
        $domain = substr(strrchr($email, "@"), 1);

        // Get MX records
        try{
            $mxRecords = dns_get_record($domain, DNS_MX);
        }catch(Exception $e){
            return response()->json(['email' => $email, 'status' => 'undeliverable','message' => $e->getMessage()], 200);
        }

        if (!$mxRecords) {
            return response()->json(['email' => $email, 'status' => 'undeliverable', 'reason' => 'No MX records found'], 200);
        }
        
        // Use the highest priority MX server
        usort($mxRecords, function ($a, $b) {
            return $a['pri'] - $b['pri'];
        });
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
            ],401);
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
            stream_set_timeout($connection, 20);
        
            $initialResponse = '';
            $maxAttempts = 10; // Maximum attempts to wait for 220 response
            $attempt = 0;

            while ($attempt < $maxAttempts) {
                $initialResponse = fgets($connection, 1024);
                if ($initialResponse && strpos($initialResponse, '220') === 0) {
                    while (($initialLine = fgets($connection, 1024)) !== false) {
                        $responses[] = trim($initialLine);
                        if (strpos($initialLine, '220 ') === 0) break; // Stop when the last 250 response is received
                    }
                    break;
                }
                usleep(500000); // Wait for 0.5 seconds before retrying
                $attempt++;
            }

            if (!$initialResponse || strpos($initialResponse, '220') !== 0) {
                throw new Exception("Unexpected or no SMTP response: " . trim($initialResponse));
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
            $responses[] = trim($mailFromResponse);
        
            // Send RCPT TO
            fwrite($connection, "RCPT TO: <$email>\r\n");
            $rcptResponse = '';
            $maxAttempts = 10; // Maximum attempts to wait for 220 response
            $attempt = 0;

            while ($attempt < $maxAttempts) {
                 $rcptResponse = fgets($connection, 1024);
                if ($rcptResponse && strpos($rcptResponse, '250') !== false || strpos($rcptResponse, '550') !== false || strpos($rcptResponse, '450') !== false || strpos($rcptResponse, '451') !== false || strpos($rcptResponse, '452') !== false || strpos($rcptResponse, '421') !== false || strpos($rcptResponse, '550-5.1.1') !== false || strpos($rcptResponse, '550 5.1.1') !== false || strpos($rcptResponse, '550-5.2.1') !== false || strpos($rcptResponse, '550 #5.1.0') !== false || strpos($rcptResponse, '550 5.7.1') !== false || strpos($rcptResponse, '550 5.4.1') !== false) {
                    break;

                }
                $attempt++;
            }

            $responses[] = trim($rcptResponse);
        
            // Send QUIT
            fwrite($connection, "QUIT\r\n");
            fclose($connection);
        
            // **Determine email status**
            if (strpos($rcptResponse, '250') !== false) {
                return ["status" => "deliverable", "data" => $responses];
            } elseif (strpos($rcptResponse, '550-5.1.1') !== false || strpos($rcptResponse, '550 5.1.1') !== false || strpos($rcptResponse, '550-5.2.1') !== false || strpos($rcptResponse, '550 #5.1.0') !== false || strpos($rcptResponse, '550') !== false) {
                return ["status" => "undeliverable", "data" => $responses];
            } elseif (strpos($rcptResponse, '550 5.7.1') !== false || strpos($rcptResponse, '550 5.4.1') !== false) {
                return ["status" => "bounce", "data" => $responses];
            } elseif (strpos($rcptResponse, '450') !== false || strpos($rcptResponse, '451') !== false || strpos($rcptResponse, '452') !== false) {
                return ["status" => "unknown", "data" => $responses];
            } elseif (strpos($rcptResponse, '421') !== false) {
                return ["status" => "undeliverable", "data" => $responses];
            } elseif (preg_match('/250.*catch/i', implode(" ", $responses))) {
                return ["status" => "accepted_all", "data" => $responses];
            }
            else {
                return ["status" => "unreachable", "data" => $responses];
            }
        } catch (Exception $e) {
            $responses[] = $e->getMessage();
            return ["status" => "unknown", "data" => $responses];
        }        

        
    }
}
