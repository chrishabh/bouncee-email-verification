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

        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json(['email' => $email, 'valid' => false, 'reason' => 'Invalid email format'], 400);
        }

        // Extract domain
        $domain = substr(strrchr($email, "@"), 1);

        // Get MX records
        $mxRecords = dns_get_record($domain, DNS_MX);
        if (!$mxRecords) {
            return response()->json(['email' => $email, 'status' => 'undeliverable', 'reason' => 'No MX records found'], 400);
        }

        $mxServer = $mxRecords[0]['target'];

        // Perform SMTP Handshake
        $smtpResponse = $this->telnetsmtpHandshake($email, $mxServer);

        return response()->json([
            'email' => $email,
            'mx-record' => $mxServer,
            'status' => $smtpResponse['status'],
            'reason' => $smtpResponse['data']
        ]);
    }

    private function smtpHandshake($email, $mxServer)
    {
        try {
            $process = new Process(["nc", "-w", "5", $mxServer, "25"]);
            $process->setTimeout(30);
            $process->run();

            if (!$process->isSuccessful()) {
                throw new ProcessFailedException($process);
            }

            $output = $process->getOutput();
            return ['valid' => true, 'reason' => $output];
            if (strpos($output, "220") === false) {
                return ['valid' => false, 'reason' => 'SMTP handshake failed'];
            }

            if (strpos($output, "450") === false) {
                return ['valid' => false, 'reason' => 'unknown'];
            }

            if (strpos($output, "550") === false) {
                return ['valid' => false, 'reason' => 'Bounce'];
            }

            return ['valid' => true, 'reason' => 'Email exists'];
        } catch (Exception $e) {
            return ['valid' => false, 'reason' => 'Error connecting to SMTP server'];
        }
    }

    private function telnetsmtpHandshake($email, $mxServer)
    {
        
        $connection = fsockopen($mxServer, 25, $errno, $errstr, 10);
        if (!$connection) {
            return "Failed to connect to SMTP server: $errstr ($errno)";
        }

        // Perform SMTP handshake
        $responses = [];
        stream_set_timeout($connection, 10);

        // Read the initial 220 response
        $responses[] = fgets($connection, 1024);

        // Send EHLO (instead of HELO)
        fwrite($connection, "EHLO ipl-wages.com\r\n");
        $responses[] = fgets($connection, 1024); // Read EHLO response

        // Read additional server responses (some servers send multiple 250 responses)
        while (($line = fgets($connection, 1024)) !== false) {
            $responses[] = trim($line);
            if (strpos($line, '250 ') === 0) break; // Stop when last 250 response is received
        }

        // Send MAIL FROM
        fwrite($connection, "MAIL FROM: <ch.rishabh8527@gmail.com>\r\n");
        $responses[] = fgets($connection, 1024); // Read MAIL FROM response

        // Send RCPT TO
        fwrite($connection, "RCPT TO: <$email>\r\n");
        $responses[] = $rcptResponse = trim(fgets($connection, 1024)); // Read RCPT TO response


        // Close the connection
        fwrite($connection, "QUIT\r\n");
        fclose($connection);

        // **Determine email status**
        if (strpos($rcptResponse, '250') !== false) {
            return ["status" => "Deliverable", "data" => $responses];
        } elseif (strpos($rcptResponse, '550') !== false) {
            return ["status" => "bounce", "data" => $responses];
        } elseif (strpos($rcptResponse, '450') !== false || strpos($rcptResponse, '451') !== false || strpos($rcptResponse, '452') !== false) {
            return ["status" => "soft_bounce", "data" => $responses];
        } elseif (strpos($rcptResponse, '421') !== false) {
            return ["status" => "undeliverable", "data" => $responses];
        } elseif (preg_match('/250.*catch/i', implode(" ", $responses))) {
            return ["status" => "accepted_all", "data" => $responses];
        } else {
            return ["status" => "unknown", "data" => $responses];
        }
    }
}
