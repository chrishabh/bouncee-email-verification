<?php

namespace App\Jobs;

use App\Http\Controllers\EmailVerificationController;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

class BulkVerification implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * Create a new job instance.
     *
     * @return void
     */
    protected $fileId;
    protected $userId;
    protected $jobUuid;
    public $timeout = 0; 
    public function __construct($fileId,$userId)
    {
        $this->fileId = $fileId;
        $this->userId = $userId;
        $this->jobUuid = null;
    }

    /**
     * Execute the job.
     *
     * @return void
     */
    public function handle()
    {
       $data = \App\Models\BulkVerificationData::getBulkVerificationData($this->fileId,$this->userId);

       foreach($data as $clientData){
            $smtp_response = EmailVerificationController::jobVerify($clientData->email);
            $data = [
                'apiStatus'         => $smtp_response['status']??'Unknown',
                'status'            => ($smtp_response && $smtp_response['status']=='Deliverable') ? 'Valid':'Invalid',
                'job_email_status'  => 'verified'
            ];
            \App\Models\BulkVerificationData::updateStatus($clientData->id,$this->fileId,$this->userId,$data);
        }

       
    }
}
