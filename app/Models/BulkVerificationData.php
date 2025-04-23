<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BulkVerificationData extends Model
{
    use HasFactory;

    protected $table = 'bulk_upload_email_file_data';

    public static function getBulkVerificationData($fileId, $userId)
    {
        return self::where('file_id', $fileId)
            ->where('importedBy', $userId)
            ->get();
    }

    public static function updateStatus($id, $fileId, $userId, $data)
    {
        return self::where('id',$id)->where('file_id', $fileId)
            ->where('importedBy', $userId)
            ->update($data);
    }
    
}
