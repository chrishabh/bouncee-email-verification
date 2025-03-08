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
            return response()->json(['email' => $email, 'valid' => false, 'reason' => 'No MX records found'], 400);
        }

        $mxServer = $mxRecords[0]['target'];

        // Perform SMTP Handshake
        $smtpResponse = $this->telnetsmtpHandshake($email, $mxServer);

        return response()->json([
            'email' => $email,
            'mx-record' => $mxServer,
            'reason' => $smtpResponse
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
        stream_set_timeout($connection, 20);

        // Read the initial 220 response
        $responses[] = fgets($connection, 1024);

        fwrite($connection, "EHLO ipl-wages.com\r\n");
        usleep(2000000);
        $responses[] = fgets($connection, 1024);

        // Specify the sender email
        fwrite($connection, "MAIL FROM: <ch.rishabh8527@gmail.com>\r\n");
        usleep(2000000);
        $responses[] = fgets($connection, 1024);

        // Specify the recipient email
        fwrite($connection, "RCPT TO: <$email>\r\n");
        usleep(2000000);
        $responses[] = fgets($connection, 1024); 

        // Close the connection
        fwrite($connection, "QUIT\r\n");
        fclose($connection);

        return $responses;

        // Check the response for recipient validation
        if (strpos($response, '250') !== false) {
            return "Email address is valid.";
        } elseif (strpos($response, '550') !== false) {
            return "Email address is invalid.";
        }

        return "Unable to verify the email address.";
    }
}
