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
        $smtpResponse = $this->smtpHandshake($email, $mxServer);

        return response()->json([
            'email' => $email,
            'valid' => $smtpResponse['valid'],
            'reason' => $smtpResponse['reason']
        ]);
    }

    private function smtpHandshake($email, $mxServer)
    {
        try {
            $process = new Process(["nc", "-w", "5", $mxServer, "25"]);
            $process->setTimeout(10);
            $process->run();

            if (!$process->isSuccessful()) {
                throw new ProcessFailedException($process);
            }

            $output = $process->getOutput();

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
}
